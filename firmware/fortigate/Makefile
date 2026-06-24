# FortiGate firmware fuzzing build.
#
# Usage:
#   make          - build agent, hook.so, inject, strategy.txt
#   make config   - regenerate strategy.txt
#   make clean

KAFL_ROOT         ?= $(abspath ../../..)
EXAMPLES_ROOT     ?= $(KAFL_ROOT)/examples
LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent

NYX_INC      := -I$(EXAMPLES_ROOT) -I$(LIBNYX_AGENT_ROOT)/src
LIBNYX_AGENT := $(LIBNYX_AGENT_ROOT)/libnyx_agent.a

COMMON_HDR := src/hook_common.h

AGENT_SRC  := src/agent.c
AGENT_OUT  := agent
HOOK_SRC   := src/hook.c
HOOK_OUT   := hook.so
HOOK_DBG_OUT := hook_dbg.so
INJECT_SRC := src/inject.c
INJECT_OUT := inject

STRATEGY_YAML := strategy.yaml
STRATEGY_TXT  := strategy.txt
GEN_SCRIPT    := ../../../fuzzer/scripts/generate_agent_config.py

CC ?= gcc
CFLAGS_COMMON ?= -O2 -Wall -Wextra
CFLAGS_AGENT  := -static $(CFLAGS_COMMON) $(NYX_INC) -I.
# -std=gnu11: avoid C23 symbol redirection (__isoc23_strtoul/sscanf@GLIBC_2.38)
# so hook.so loads on the target's older glibc.
CFLAGS_HOOK   := -m64 -shared -fPIC -std=gnu11 $(CFLAGS_COMMON) $(NYX_INC) -I.
CFLAGS_HOOK_DBG := -m64 -shared -fPIC -std=gnu11 -O0 -g3 -Wall -Wextra -fno-omit-frame-pointer $(NYX_INC) -I.
LDFLAGS_HOOK  := -Wl,-Bsymbolic-functions
CFLAGS_INJECT := -static -m64 $(CFLAGS_COMMON)
LDFLAGS_AGENT := $(LIBNYX_AGENT) -ldl -lpthread

.DEFAULT_GOAL := all
.PHONY: all build_agent build_hook build_hook_dbg build_inject config clean

all: $(AGENT_OUT) $(HOOK_OUT) $(INJECT_OUT) $(STRATEGY_TXT)

build_agent: $(AGENT_OUT)
build_hook: $(HOOK_OUT)
build_hook_dbg: $(HOOK_DBG_OUT)
build_inject: $(INJECT_OUT)
config: $(STRATEGY_TXT)

$(AGENT_OUT): $(AGENT_SRC) $(COMMON_HDR) $(LIBNYX_AGENT)
	$(CC) $(CFLAGS_AGENT) -o $@ $(AGENT_SRC) $(LDFLAGS_AGENT)
	@echo "[+] Built: $@"
	@file $@

$(HOOK_OUT): $(HOOK_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS_HOOK) -o $@ $(HOOK_SRC) $(LDFLAGS_HOOK) -ldl
	@echo "[+] Built: $@"
	@file $@

$(HOOK_DBG_OUT): $(HOOK_SRC) $(COMMON_HDR)
	$(CC) $(CFLAGS_HOOK_DBG) -o $@ $(HOOK_SRC) $(LDFLAGS_HOOK) -ldl
	@echo "[+] Built: $@"
	@file $@

$(INJECT_OUT): $(INJECT_SRC)
	$(CC) $(CFLAGS_INJECT) -o $@ $(INJECT_SRC)
	@echo "[+] Built: $@"
	@file $@

$(STRATEGY_TXT): $(STRATEGY_YAML) $(GEN_SCRIPT)
	python3 $(GEN_SCRIPT) --strategy $(STRATEGY_YAML) --output $(STRATEGY_TXT) --seed-dir .
	@echo "[+] Generated: $@"

clean:
	rm -f $(AGENT_OUT) $(HOOK_OUT) $(HOOK_DBG_OUT) $(INJECT_OUT) $(STRATEGY_TXT)
	@echo "[+] Cleaned fortigate build artifacts"
