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

#### 什么是GOT overwrite技术
这种技术帮助攻击者将一个function的GOT entry地址改写为一个特定的地址，我们知道function的got位置是不变的，这样一个任意地址修改的漏洞，就可以造成GOT overwrite，而通过libc中的offset，我们可以计算出需要调用函数的地址
```
offset_diff = execve_addr - getuid_addr
GOT[getuid] = GOT[getuid] + offset_diff
```
#### 什么是GOT dereference技术
This technique is similar to GOT overwrite, but here instead of overwriting the GOT entry of a particular libc function, its value is copied into a register and offset difference is added to the register content. Thus now the register contains required libc function address. For example GOT[getuid] contains getuid function address, which gets copied to a register. The difference in the offsets of two libc functions (execve and getuid) gets added to register contents. Now jumping to the register value invokes execve!!
```
offset_diff = execve_addr - getuid_addr
eax = GOT[getuid]
eax = eax + offset_diff
```
Both the technique looks simpler, but how to perform these actions in runtime when a buffer overflow occurs?!? We need to identify a function (which does these additions and copying the result to register) and jump to that particular function to achieve GOT overwrite/dereference. But obviously no single function (neither in libc nor in our executable) does it for us!! In such cases ROP is used.

#### 使用ROP覆盖got