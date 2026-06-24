#!/bin/bash
# Attach GDB to FortiGate VM and break on SSL_read
#
# FortiGate's HTTPS daemon handles SSL. The binary is 32-bit PIE on older
# FortiOS releases (or 64-bit on recent ones). Adjust calling convention as
# needed.
#
# For 32-bit (from old Ivanti context):
#   SSL_read(SSL *ssl, void *buf, int num)
#     - 1st arg (ssl)   at esp+4
#     - 2nd arg (buf)   at esp+8
#     - 3rd arg (num)   at esp+12
#     - return value in eax
#
# For 64-bit (FortiOS 7.x): args in rdi, rsi, rdx, return in rax.

gdb \
    -ex "set pagination off" \
    -ex "target remote 192.168.122.43:23" 
    #-ex " b *0xDCAAC0"
