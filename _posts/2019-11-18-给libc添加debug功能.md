---
layout: post
title: 给libc添加debug symbol
excerpt: "给libc添加debug symbol的操作方法"
categories: [知识总结]
comments: true
---


```shell
wget http://ftp.gnu.org/gnu/libc/glibc-2.19.tar.gz
tar xvf glibc-2.19.tar.gz
cd glibc-2.19/
mkdir build
cd build
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" ../configure --prefix=/root/sploitfun/gccwget/glibc-2.19/64
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
继续
```
make install
```
结果
```
			       /root/sploitfun/gccwget/glibc-2.19/64/lib /root/sploitfun/gccwget/glibc-2.19/64/lib
/root/sploitfun/gccwget/glibc-2.19/build/elf/ldconfig: Warning: ignoring configuration file that cannot be opened: /root/sploitfun/gccwget/glibc-2.19/64/etc/ld.so.conf: No such file or directory
make[1]: Leaving directory `/root/sploitfun/gccwget/glibc-2.19'

```
在`/root/sploitfun/gccwget/glibc-2.19/64/lib`目录下会有`libc.so.6`文件


---

查看ld版本
```
ls -al /lib/ld-linux.so.2
lrwxrwxrwx 1 root root 10 10月 23 16:34 /lib/ld-linux.so.2 -> ld-2.17.so
```

export LD_LIBRARY_PATH=/root/sploitfun/gccwget/glibc-2.19/64/lib/

export LD_PRELOAD=/root/sploitfun/gccwget/glibc-2.19/64/lib/libc.so.6

编译可用版本:
```
gcc -g -z norelro -z execstack -o vuln vuln.c -Wl,--rpath=/root/sploitfun/gccwget/glibc-2.19/64/lib -Wl,--dynamic-linker=/root/sploitfun/gccwget/glibc-2.19/64/lib/ld-linux-x86-64.so.2
```

#### 升级到gcc 6.3：
```bash
yum -y install centos-release-scl
yum -y install devtoolset-6-gcc devtoolset-6-gcc-c++ devtoolset-6-binutils
scl enable devtoolset-6 bash
```
需要注意的是scl命令启用只是临时的，退出shell或重启就会恢复原系统gcc版本。
如果要长期使用gcc 6.3的话：
```bash
echo "source /opt/rh/devtoolset-6/enable" >>/etc/profile
```
这样退出shell重新打开就是新版的gcc了