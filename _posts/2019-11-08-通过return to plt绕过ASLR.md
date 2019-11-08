---
layout: post
title: 通过return to plt绕过ASLR
excerpt: "sploitfun系列教程之2.3.1 return_to_plt"
categories: [sploitfun系列教程]
comments: true
---

#### 什么是ASLR
Address space layout randomization (ASLR)是一种地址随机化的技术，随机化的空间包括
- 栈地址
- 堆地址
- 共享库地址

在以前的文章中，libc中函数地址计算方法如下
```
libc function address = libc base address + function offset
```
其中
- 当地址随机化关闭，libc的基地址通常是`0xb7e22000`
- offset通过`readelf -s libc.so.6 | grep`来查看

现在我们把地址随机化开启
```
echo 2 > /proc/sys/kernel/randomize_va_space
```
现在libc基地址将会被随机化


一个例子
```c
//eg.c
//$gcc -g -o eg eg.c
#include <stdio.h>

int main(int argc, char* argv[]) {
 printf("Hello %s\n", argv[1]);
 return 0;
}
```
编译
```shell
gcc -g -o eg eg.c -m32
```
下面的反汇编显示，我们不会直接调用'printf'，而是调用相应的PLT代码'printf@PLT'。
```bash
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0804840d <+0>:	push   ebp
   0x0804840e <+1>:	mov    ebp,esp
   0x08048410 <+3>:	and    esp,0xfffffff0
   0x08048413 <+6>:	sub    esp,0x10
   0x08048416 <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048419 <+12>:	add    eax,0x4
   0x0804841c <+15>:	mov    eax,DWORD PTR [eax]
   0x0804841e <+17>:	mov    DWORD PTR [esp+0x4],eax
   0x08048422 <+21>:	mov    DWORD PTR [esp],0x80484d4
   0x08048429 <+28>:	call   0x80482e0 <printf@plt>
   0x0804842e <+33>:	mov    eax,0x0
   0x08048433 <+38>:	leave  
   0x08048434 <+39>:	ret    
End of assembler dump.
```
```bash
gdb-peda$ disassemble 0x80482e0
Dump of assembler code for function printf@plt:
   0x080482e0 <+0>:	jmp    DWORD PTR ds:0x804a00c
   0x080482e6 <+6>:	push   0x0
   0x080482eb <+11>:	jmp    0x80482d0
End of assembler dump.
```
在第一次调用printf之前，GOT entry (0x804a00c)指向了第二行，最终在dynamic linker帮助下完成链接
```
gdb-peda$ x/wx 0x804a00c
0x804a00c:	0x080482e6
```
