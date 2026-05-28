# edit by verf1sh: strategy-driven fuzz agent build (kAFL)
#
# Builds:
#   agent               - 64-bit static agent (runs in VM, TLS + kAFL hypercalls)
#   hook_SSL_read.so    - 32-bit LD_PRELOAD hook (intercepts SSL_read in VM)
#
# Prerequisite:
#   source kafl/env.sh  (sets EXAMPLES_ROOT, KAFL_WORKDIR)
#
# Usage:
#   make                - Build both
#   make build_agent    - Build agent only
#   make build_hook     - Build hook only
#   make clean          - Remove build artifacts

KAFL_ROOT         ?= $(abspath ../../..)
EXAMPLES_ROOT     ?= $(KAFL_ROOT)/examples
LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent

NYX_INC      := -I$(EXAMPLES_ROOT) -I$(LIBNYX_AGENT_ROOT)/src
LIBNYX_AGENT := $(LIBNYX_AGENT_ROOT)/libnyx_agent.a

AGENT_SRC  := src/agent.c
AGENT_OUT  := agent
HOOK_SRC   := src/hook_SSL_read.c
HOOK_OUT   := hook_SSL_read.so

CFLAGS_HOOK  := -m32 -shared -fPIC -O2 -Wall
CFLAGS_AGENT := -static -O2 -Wall $(NYX_INC)
LDFLAGS_AGENT := $(LIBNYX_AGENT) -lssl -lcrypto -ldl -lpthread

.DEFAULT_GOAL := all
.PHONY: all build_agent build_hook clean

all: $(AGENT_OUT) $(HOOK_OUT)

build_agent: $(AGENT_OUT)

build_hook: $(HOOK_OUT)

$(AGENT_OUT): $(AGENT_SRC) $(LIBNYX_AGENT)
	gcc $(CFLAGS_AGENT) -o $@ $< $(LDFLAGS_AGENT)
	@echo "[+] Built: $@"
	@file $@

$(HOOK_OUT): $(HOOK_SRC)
	gcc $(CFLAGS_HOOK) -o $@ $< -ldl
	@echo "[+] Built: $@"
	@file $@

clean:
	rm -f $(AGENT_OUT) $(HOOK_OUT)
	@echo "[+] Cleaned ivanti build artifacts"
