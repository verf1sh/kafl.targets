# FortiGate httpsd kAFL Hook 排障总结

本文记录 FortiGate `httpsd` 使用 `hook.so` 接入 kAFL fuzz 的排障过程。最终状态已经跑通：kAFL 能进入 hook，payload 能喂给 `httpsd`，并且 GUI 中能看到覆盖率、路径和 execs 持续增长。

## 背景：从 Ivanti LD_PRELOAD 经验迁移到 FortiGate

一开始的思路是参考 Ivanti 目标上的 `LD_PRELOAD` hook 方案：在目标服务启动前预加载 hook so，让动态链接器自然完成符号 interpose，然后在输入函数附近接入 kAFL。这个思路在 Ivanti 场景中比较顺，因为目标服务的启动方式和环境变量可控，hook 可以跟随进程启动一起加载，符号解析也处在正常的 preload 优先级模型里。

FortiGate 的情况不一样。`httpsd` 是 FortiOS 里由 `/bin/init` 管理的多进程/prefork 服务，实际运行时会有多个 `/bin/httpsd` worker。它的启动环境不可控，不能像普通 Linux 服务一样稳定加 `LD_PRELOAD` 后重启服务；手动 `killall httpsd` 也不适合作为 fuzz 流程的一部分，因为 FortiOS supervision 会重新拉起 worker 池，过程中可能出现旧 worker 未退出、新 worker 已启动、进程数量短暂翻倍等状态。也就是说，不能假设“重启一次服务，然后所有 worker 都带着 LD_PRELOAD 干净启动”。

因此适配 FortiGate 时只能改成后期注入模型：等 `httpsd` worker 已经启动后，通过 ptrace 调用远程 `dlopen("/hook.so")`，把 hook 注入到所有现存 worker 中。这个转变带来了后续一系列问题：

- 必须处理多 worker 请求分发，单独注入一个 PID 不代表真实请求会命中该进程；
- 后期 `dlopen` 的 DSO 不再享受启动期 `LD_PRELOAD` 那种简单优先级模型，容易暴露 ELF 符号抢占问题；
- 已经完成 relocation 的主程序、libc、libapr 需要额外 patch GOT 或 libc entry；
- `dlopen` 同一路径会复用旧 handle，调试时重新上传同名 so 不一定生效；
- 不能依赖手动重启服务来获得干净环境，正式 fuzz 要由脚本等待 worker 稳定后批量注入。

这也是本次适配比 Ivanti 更复杂的根本原因：不是协议 hook 本身复杂，而是 FortiGate 的服务管理方式、worker 模型和后期注入模型叠加后，导致输入点确认、注入覆盖、符号解析和 kAFL snapshot 时机都必须重新验证。

## 给领导看的简要总结

最近一周主要工作不是单纯“写一个 hook”，而是在把 kAFL 的 in-target fuzz 模型适配到 FortiGate `httpsd` 的真实运行方式。FortiGate 的 `httpsd` 不是普通单进程服务，而是由 `/bin/init` 拉起的多 worker/prefork 模型，环境变量不可控，LD_PRELOAD 不适用，只能用 ptrace 后期 `dlopen` 注入 `hook.so`。这带来了几个叠加问题：注入目标可能不是实际处理请求的 worker；后期注入的 DSO 与已加载主程序/libc/libapr 存在 ELF 符号抢占；kAFL payload 接管 `read()` 后真实浏览器请求不再直接进入 handler；PT range 既可以由 `kafl.yaml` 静态配置，也可以由 hook 动态提交，两个来源重叠会让 libxdc 直接 abort。

最终解决路径是把问题收敛到最小链路：只保留已动态确认的 `accept()/accept4() -> read(client_fd)`，删除/停用宽泛 hook、ptrace syscall 注入、write/close RELEASE、命令注入辅助检测和动态 PT range 提交等高风险逻辑；用 `static hook_read_impl()` 规避 ELF 符号抢占；用 `/inject httpsd /hook.so` 注入所有 worker；用 `kafl.yaml ip0` 作为唯一 PT range 来源。最终 kAFL GUI 显示 execs、paths、bitmap edges/blocks 均持续增长，说明覆盖率反馈已经跑通。

## 这一周主要卡点

1. **Ivanti 的 LD_PRELOAD 模型不能直接复用。** FortiGate `httpsd` 由 `/bin/init` 管理，环境变量不可控，手动重启不稳定，无法保证所有 worker 从启动期加载 hook。
2. **多 worker 模型导致单 PID 验证结果不稳定。** 单独注入一个 PID 只能证明 hook 本身可加载，不能保证请求命中该 worker。正式 fuzz 必须注入所有 `/bin/httpsd` worker。
3. **输入点定位不是一开始就确定的。** 最初并不能确认 FortiGate `httpsd` 的请求体最终走 `read`、`recv`、`readv` 还是直接 syscall。通过 GDB 栈确认了真实路径是 `apr_socket_recv() -> libc read()`，所以最终 hook 面收敛到 `accept/read`。
4. **后期 `dlopen` 注入触发 ELF 符号抢占。** `(void *)read` 被解析成主程序 `read@plt`，导致 libc `read` 被 patch 回 PLT，hook 的 `read` 永远不触发。这是最隐蔽、耗时最大的根因。
5. **手工调试和 kAFL 正式运行模式容易混淆。** 手工访问 URL 时应该关闭 `/dev/shm/kafl_hook_enable`；正式 fuzz 时该文件存在，真实网络请求会被 kAFL payload 替换。
6. **PT range 配置来源冲突。** `kafl.yaml` 已经提供 `ip0`，hook 再提交同一 text mapping 会造成 range overlap，libxdc 在 `NEXT_PAYLOAD` 时 abort。

## 前期探索方案存在的问题

前期 Claude/其他尝试的思路提供了不少方向，但很多方案偏“全量 hook”或“绕过输入点”，在 FortiGate 这个目标上放大了复杂度。主要问题如下。

### 1. 大而全 hook 面过宽

早期 `hook.c.bak_full` 尝试同时 hook：

```text
read / recv / recvfrom / readv / recvmsg
write / send / sendto / close
accept / accept4
syscall
system / popen / exec*
```

这个方向的问题是：

- hook 面太宽，很难判断真正命中的 API 是哪个；
- `recvmsg`、Unix socket、SCM_RIGHTS 等内部通信也可能被误伤；
- hook `write/close` 做 RELEASE 会把响应路径和生命周期也卷入 fuzz loop，调试面扩大；
- hook `syscall()` 试图覆盖 libc bypass，但会增加 ABI/varargs/递归风险；
- 命令注入检测逻辑和当前“先跑通 pre-auth HTTP 覆盖率”的目标无关，增加噪声。

最终证据显示 FortiGate 当前 HTTP 请求路径是：

```text
accept()/accept4() -> apr_socket_recv() -> libc read()
```

因此最终版本只保留 `accept/accept4/read`。

### 2. ptrace syscall 注入路线不适合作为最终 fuzz 数据面

`inject.c` 中曾实现 `--trace/--learn`，通过 ptrace 跟踪 syscall，并在 `read` syscall 返回后改 buffer 或跳过 read。这对定位输入点有帮助，但不适合作为最终 kAFL fuzz 主路径：

- 每个 syscall stop 都要 ptrace 往返，性能低；
- 多 worker 下请求可能被未 attach 的 worker 抢走；
- syscall entry/exit 状态管理复杂，容易和 accept/poll/read 状态交错；
- 很难和 kAFL snapshot/reload 模型稳定结合；
- 最终还是需要在目标进程内部执行 `NEXT_PAYLOAD/ACQUIRE/RELEASE`。

所以 ptrace tracer 只保留为诊断工具，正式方案改为 in-target hook：`hook.so` 自己在 `read(client_fd)` 内进入 kAFL 流程。

### 3. 依赖 `write/close` 触发 RELEASE 的模型过早复杂化

早期设计里希望：

```text
read(client_fd)  -> ACQUIRE + copy payload
write/close(fd)  -> RELEASE
```

这个模型理论上完整，但实际调试时会引入几个问题：

- 响应发送可能走 `write/send/sendto` 中多个路径；
- Apache/APR 内部 fd 生命周期复杂，不容易精确判断哪个 fd 是 fuzz client；
- close hook 容易影响非目标 fd；
- 问题还没确认在 input hook 前，先 hook output 侧会让故障定位更困难。

最终版本先用最小输入链路验证覆盖率，避免把 RELEASE 绑定到复杂输出路径。当前重点是证明 kAFL payload 能进入 parser 并产生 PT coverage。

### 4. 动态 PT range 提交和静态 ip0 同时存在

前期方案里 hook 会从 `/proc/self/maps` 计算 `/httpsd` 或 `/bin/init` text range，再提交给 kAFL：

```c
submit_self_text_ranges();
```

但 `kafl.yaml` 已经配置：

```yaml
ip0: 0x43f000-0x3073000
```

两个范围重叠后，libxdc 在初始化 decoder 时直接 assert。最终采用方案 A：只使用 `kafl.yaml ip0`，hook 默认不再动态提交 PT range。

### 5. 没有区分“验证 hook”与“正式 fuzz”

前期调试中曾在 guest 中直接运行：

```sh
/start_fuzz.sh
```

这会同时注入 hook、创建 kAFL gate、启动 agent 并触发 hypercall。如果不是由 kAFL host/worker 正式启动，很容易把普通手工调试 VM 带入不完整的 kAFL 状态。

最终流程区分为：

- 手工验证注入：`RUN_AGENT=0 /start_fuzz.sh`
- 正式 fuzz：host 侧运行 `kafl fuzz ...`

## 最终跑通状态

最终 kAFL GUI 中确认：

- `#Execs` 持续增长
- `CurExec/s` 正常
- `Paths Total` 增长
- `Bitmap Edges/Blocks` 非 0
- `Stability 100%`
- `Timeouts 0%`

这说明：

```text
kAFL host -> guest agent -> httpsd hook -> hook_read_impl -> fuzz_read -> httpsd parser -> PT coverage
```

整条链路已经打通。

## 最终启动命令

在 host 上启动，不要在 guest 里手动直接运行 `/start_fuzz.sh`：

```sh
cd /home/verf1sh/fuzzing/kAFL/kafl/examples/firmware/fortigate

kafl fuzz \
  -w /tmp/fgt-kafl \
  --purge \
  -p 1 \
  -D \
  --seed-dir /home/verf1sh/fuzzing/kAFL/kafl/examples/firmware/fortigate/seeds \
  --log-hprintf
```

观察 GUI：

```sh
kafl gui -w /tmp/fgt-kafl
```

观察 hprintf：

```sh
tail -f /tmp/fgt-kafl/hprintf_*.log
```

## 问题 1：只注入单个 httpsd worker

### 现象

手动注入单个 PID 后，GDB 能看到该进程里 `/hook.so` 已加载，但访问 URL 时断点不稳定，有时 `accept` 能停，有时 `read` 或 handler 不停。

### 根因

FortiGate 的 `httpsd` 是多进程/prefork 模型。请求会被任意 worker 接收。

只注入单个 PID 时，请求不一定落到这个 PID，所以可能出现：

```text
hook mapped 但请求未命中该进程
accept/read 断点不触发
snapshot=0
read_hits=0
coverage 不动
```

### 解决

正式 fuzz 时必须注入所有 `/bin/httpsd` worker。

`start_fuzz.sh` 中使用：

```sh
/inject httpsd /hook.so
```

并检查：

```text
hook mapping summary: mapped=N total=N
```

## 问题 2：`read` hook 实际跳到了 `read@plt`

### 现象

`/hook.so` 成功注入，`accept` hook 能断住，但 `read` hook 一直断不住。

GDB 中检查 libc `read`：

```gdb
x/12i read
```

看到：

```text
<read>: movabs rax,0x4478f0
        jmp    rax
```

进一步检查：

```gdb
x/gx 0x4478f0
```

发现：

```text
0x4478f0 <read@plt>
```

也就是说，libc `read` 被 patch 后没有跳到 `/hook.so`，而是跳回了主程序的 `read@plt`。

### 根因

原代码中使用：

```c
patch_function_entry("read", (void *)read);
```

注入 DSO 后，`read` 是全局符号，会参与 ELF 动态符号解析。`(void *)read` 并不一定指向 hook.so 自己的 `read`，可能被解析成主程序或其他对象里的 `read@plt`。

最终导致错误控制流：

```text
libc read -> read@plt
```

而不是：

```text
libc read -> hook.so read
```

所以在 `/hook.so` 的 `read` 地址下断点不会停。

### 解决

引入静态内部实现函数：

```c
static ssize_t hook_read_impl(int fd, void *buf, size_t count);
static int hook_accept_impl(int fd, struct sockaddr *addr, socklen_t *addrlen);
static int hook_accept4_impl(int fd, struct sockaddr *addr,
                             socklen_t *addrlen, int flags);
```

导出的 `read/__read/__libc_read` 只做 wrapper：

```c
ssize_t read(int fd, void *buf, size_t count)
{
    return hook_read_impl(fd, buf, count);
}
```

真正写入 libc/GOT 的地址改成：

```c
patch_function_entry("read", (void *)hook_read_impl);
patch_function_entry("__read", (void *)hook_read_impl);
patch_function_entry("__libc_read", (void *)hook_read_impl);
```

同时 `replacement_for_symbol()` 也返回 `hook_read_impl`。

Makefile 中增加链接保险：

```make
LDFLAGS_HOOK := -Wl,-Bsymbolic-functions
```

修复后 GDB 中看到：

```text
<read>: movabs rax,0x7f62b507634f
        jmp    rax

0x7f62b507634f <hook_read_impl>
```

说明控制流已经正确变为：

```text
libc read -> hook_read_impl
```

## 问题 3：复用旧 `/hook.so` 路径导致旧代码仍在进程中

### 现象

重新编译并上传 `/hook.so` 后，再次 `/inject <pid> /hook.so`，行为没有变化。

### 根因

同一进程内 `dlopen("/hook.so")` 如果之前已经加载过，动态链接器可能直接返回已有 handle，不会重新加载新文件，也不会重新执行 constructor。

### 解决

调试时使用新文件名：

```sh
cp /hook.so /hook2.so
/inject <pid> /hook2.so
```

正式 fuzz 前重启 VM 或换新的 `httpsd` worker 池，确保加载的是新 hook。

## 问题 4：开启 kAFL 后真实请求不到 handler

### 现象

未注入 hook 时，手动访问 URL 能命中 login handler 断点。注入 hook 并进入 kAFL 后，真实请求不再正常到 handler。

### 根因

这是预期行为。`/dev/shm/kafl_hook_enable` 存在时，`fuzz_read()` 会接管 socket `read`，返回 kAFL payload，而不再返回真实网络请求数据。

控制流变成：

```text
read(client_fd) -> hook_read_impl -> fuzz_read -> copy kAFL payload to buf
```

因此 handler 是否命中取决于当前 kAFL payload 是否构造成对应 HTTP 请求，而不是手动浏览器请求。

### 解决

调试真实请求路径时关闭 gate：

```sh
rm -f /dev/shm/kafl_hook_enable
```

正式 fuzz 时开启 gate：

```sh
touch /dev/shm/kafl_hook_enable
```

`start_fuzz.sh` 在正式模式下会自动创建该文件。

## 问题 5：手动运行 `/start_fuzz.sh` 导致 QEMU/kAFL 崩溃

### 现象

在 guest 中直接运行：

```sh
/start_fuzz.sh
```

导致 QEMU/kAFL 崩溃或异常。

### 根因

`/start_fuzz.sh` 不只是注入 hook，它还会启动 `/agent`，并触发 kAFL hypercall。普通手工调试 VM 或非完整 kAFL worker 环境中直接执行，容易让 QEMU 进入不匹配状态。

### 正确用法

正式 fuzz 时由 host 启动：

```sh
kafl fuzz ...
```

kAFL/QEMU 启动 guest 后再由配置执行 `/start_fuzz.sh`。

如果只是想手动验证注入，不启动 kAFL agent：

```sh
RUN_AGENT=0 /start_fuzz.sh
```

## 问题 6：PT range 重叠导致 libxdc assert

### 现象

kAFL 崩溃：

```text
qemu-system-x86_64: src/disassembler.c:362: init_disassembler:
Assertion `!in_range_specific(self->min_addr_0, self->min_addr_1, self->max_addr_1)' failed.
```

backtrace 显示崩在：

```text
libxdc_init
pt_init_decoder
handle_hypercall_kafl_next_payload
```

### 根因

`kafl.yaml` 中已经配置了静态 PT range：

```yaml
ip0: 0x43f000-0x3073000
```

同时 hook 中又执行：

```c
submit_self_text_ranges();
```

该函数从 `/proc/self/maps` 找 `/httpsd` 或 `/bin/init` 的 executable mapping，再通过 `HYPERCALL_KAFL_RANGE_SUBMIT` 提交到 `ip1/ip2/ip3`。

结果 `ip0` 与 hook 动态提交的范围重叠，libxdc 初始化 PT decoder 时直接 assert。

### 解决

方案 A，最终采用：

保留 `kafl.yaml` 静态范围：

```yaml
ip0: 0x43f000-0x3073000
```

hook 默认不再提交运行时 text range：

```c
#ifndef HOOK_SUBMIT_TEXT_RANGES
#define HOOK_SUBMIT_TEXT_RANGES 0
#endif
```

`kafl_setup()` 中：

```c
#if HOOK_SUBMIT_TEXT_RANGES
    submit_self_text_ranges();
#else
    hprintf("[HOOK] PT range submit skipped; using kafl.yaml ip0\n");
#endif
```

这样 PT range 只由 `kafl.yaml` 提供，不会重叠。

方案 B，备用：

如果未来想用 hook runtime 计算范围，可以把 `kafl.yaml` 的 `ip0` 改成不重叠的 dummy 范围：

```yaml
ip0: 0x1000-0x2000
```

然后启用：

```c
#define HOOK_SUBMIT_TEXT_RANGES 1
```

并保持动态提交从 `id = 1` 开始，避免覆盖 `ip0`。

## 最终关键修复点

本次最终能跑通，依赖以下关键修复：

1. `read` patch 目标改为 `static hook_read_impl`，避免 ELF 符号抢占。
2. Makefile 增加 `-Wl,-Bsymbolic-functions`。
3. hook 面收敛到已验证路径：`accept()/accept4() -> read(client_fd)`。
4. 正式 fuzz 注入所有 `httpsd` worker，而不是单个 PID。
5. 调试时避免复用旧 `/hook.so` handle。
6. 认识到 kAFL gate 开启后真实请求会被 payload 替换。
7. 禁止 hook 重复提交 PT text range，避免和 `kafl.yaml ip0` 重叠。
8. 将 ptrace syscall 注入保留为诊断工具，正式数据面改为 in-target hook。

## 快速检查清单

启动前：

```sh
make -B build_hook
```

guest 中确认 `/hook.so` 是最新版本。

启动：

```sh
cd /home/verf1sh/fuzzing/kAFL/kafl/examples/firmware/fortigate
kafl fuzz -w /tmp/fgt-kafl --purge -p 1 -D \
  --seed-dir /home/verf1sh/fuzzing/kAFL/kafl/examples/firmware/fortigate/seeds \
  --log-hprintf
```

看 GUI：

```sh
kafl gui -w /tmp/fgt-kafl
```

看日志：

```sh
tail -f /tmp/fgt-kafl/hprintf_*.log
```

关键日志：

```text
[+] hook mapped pid=...
[*] hook mapping summary: mapped=N total=N
[HOOK] PT range submit skipped; using kafl.yaml ip0
[HOOK] setup done pid=...
[AGENT] HOOK DIAG: ... read_hits=... snapshot=1 cr3=1
```

关键 GUI 指标：

```text
#Execs       持续增长
CurExec/s    非 0
Paths Total  增长
Bitmap Edges 非 0
Stability    接近 100%
Timeouts     接近 0%
```
