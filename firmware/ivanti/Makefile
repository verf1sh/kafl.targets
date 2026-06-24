# edit by verf1sh: strategy-driven fuzz agent build (kAFL)
#
# Builds:
#   agent               - 64-bit static agent (runs in VM, TLS + kAFL hypercalls)
#   hook_SSL_read.so    - 32-bit LD_PRELOAD hook (intercepts SSL_read in VM)
#   strategy.txt        - Agent config generated from strategy.yaml
#
# Prerequisite:
#   source kafl/env.sh  (sets EXAMPLES_ROOT, KAFL_WORKDIR)
#
# Usage:
#   make                - Build agent + hook + strategy.txt
#   make build_agent    - Build agent only
#   make build_hook     - Build hook only
#   make config         - Generate strategy.txt from strategy.yaml
#   make clean          - Remove build artifacts

KAFL_ROOT         ?= $(abspath ../../..)
EXAMPLES_ROOT     ?= $(KAFL_ROOT)/examples
LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent

NYX_INC      := -I$(EXAMPLES_ROOT) -I$(LIBNYX_AGENT_ROOT)/src
LIBNYX_AGENT := $(LIBNYX_AGENT_ROOT)/libnyx_agent.a

COMMON_HDR := src/hook_common.h

AGENT_SRC  := src/agent.c
AGENT_OUT  := agent
HOOK_SRC   := src/hook_SSL_read.c
HOOK_OUT   := hook_SSL_read.so

STRATEGY_YAML  := strategy.yaml
STRATEGY_TXT   := strategy.txt
GEN_SCRIPT     := ../../../fuzzer/scripts/generate_agent_config.py

CFLAGS_HOOK  := -m32 -shared -fPIC -O2 -Wall -I.
CFLAGS_AGENT := -static -O2 -Wall $(NYX_INC) -I.
LDFLAGS_AGENT := $(LIBNYX_AGENT) -lssl -lcrypto -ldl -lpthread

.DEFAULT_GOAL := all
.PHONY: all build_agent build_hook config clean

all: $(AGENT_OUT) $(HOOK_OUT) $(STRATEGY_TXT)

config: $(STRATEGY_TXT)

build_agent: $(AGENT_OUT)

build_hook: $(HOOK_OUT)

$(AGENT_OUT): $(AGENT_SRC) $(COMMON_HDR) $(LIBNYX_AGENT)
	gcc $(CFLAGS_AGENT) -o $@ $(AGENT_SRC) $(LDFLAGS_AGENT)
	@echo "[+] Built: $@"
	@file $@

$(HOOK_OUT): $(HOOK_SRC) $(COMMON_HDR)
	gcc $(CFLAGS_HOOK) -o $@ $(HOOK_SRC) -ldl
	@echo "[+] Built: $@"
	@file $@

$(STRATEGY_TXT): $(STRATEGY_YAML) $(GEN_SCRIPT)
	python3 $(GEN_SCRIPT) --strategy $(STRATEGY_YAML) --output $(STRATEGY_TXT) --seed-dir .
	@echo "[+] Generated: $@"

clean:
	rm -f $(AGENT_OUT) $(HOOK_OUT) $(STRATEGY_TXT)
	@echo "[+] Cleaned ivanti build artifacts"
