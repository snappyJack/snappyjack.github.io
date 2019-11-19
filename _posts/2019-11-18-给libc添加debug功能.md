---
layout: post
title: 给libc添加debug功能
excerpt: "给libc添加debug功能的操作方法"
categories: [操作记录]
comments: true
---


```shell
wget wget http://ftp.gnu.org/gnu/libc/glibc-2.18.tar.gz
tar xvf glibc-2.18.tar.gz
cd glibc-2.18/
mkdir build
cd build
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" ../configure --prefix=/root/sploitfun/gccwget/glibc-2.18/64
```
结果
```shell
...
...
checking for old glibc 2.0.x headers... no
checking whether -fPIC is default... no
configure: creating ./config.status
config.status: creating config.make
config.status: creating Makefile
config.status: creating config.h
config.status: executing default commands

```
编译
```
make -j8
```
编译完成之后,就有了带debug的glibc,结果如下
```
...
...
bc.so.6 /root/sploitfun/gccwget/glibc-2.18/build/libc_nonshared.a -Wl,--as-needed /root/sploitfun/gccwget/glibc-2.18/build/elf/ld.so -Wl,--no-as-needed -lgcc  `gcc  --print-file-name=crtend.o` /root/sploitfun/gccwget/glibc-2.18/build/csu/crtn.o
make[2]: 离开目录“/root/sploitfun/gccwget/glibc-2.18/elf”
make[1]: 离开目录“/root/sploitfun/gccwget/glibc-2.18”
```