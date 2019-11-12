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
gcc -fno-stack-protector -o vuln vuln.c -m32
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
