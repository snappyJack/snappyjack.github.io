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
通过`readelf -s /usr/lib/libc-2.17.so | grep system`查看system的offset
```
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
sh.位置为0e5ce


### 未完待续