---
layout: post
title: SystemTap安装 
excerpt: "SystemTap安装教程"
categories: [知识总结]
comments: true
---

https://www.cnblogs.com/wipan/p/9333623.html

官方安装向导：
https://sourceware.org/systemtap/SystemTap_Beginners_Guide/using-systemtap.html#using-setup
#### 环境
- Linux发行版本：CentOS Linux release 7.4.1708 (Core)
- 内核版本：3.10.0-693.2.2.el7.x86_64
- uname -a: Linux hostname 3.10.0-693.2.2.el7.x86_64 #1 SMP Tue Sep 12 22:26:13 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

#### 安装SystemTap
先安装如下两个RPM包：

- systemtap
- systemtap-runtime

```bash
yum install systemtap systemtap-runtime
```
在运行SystemTap之间，还需要装必要的内核信息包。在现代系统上，可以运行如下stap-prep来安装这些包，如下：
```bash
# stap-prep
Need to install the following packages:
kernel-devel-3.10.0-693.2.2.el7.x86_64
kernel-debuginfo-3.10.0-693.2.2.el7.x86_64
Loaded plugins: fastestmirror
Loading mirror speeds from cached hostfile
No package kernel-devel-3.10.0-693.2.2.el7.x86_64 available.
No package kernel-debuginfo-3.10.0-693.2.2.el7.x86_64 available.
Error: Nothing to do
Loaded plugins: fastestmirror
Loading mirror speeds from cached hostfile
Could not find debuginfo for main pkg: kernel-3.10.0-693.2.2.el7.x86_64
No debuginfo packages available to install
package kernel-devel-3.10.0-693.2.2.el7.x86_64 is not installed
package kernel-debuginfo-3.10.0-693.2.2.el7.x86_64 is not installed
problem installing rpm(s) kernel-devel-3.10.0-693.2.2.el7.x86_64 kernel-debuginfo-3.10.0-693.2.2.el7.x86_64
```
SystemTap需要安装内核内核符号文件来probe内核。必要的内核信息包含在如下三个包中：
- kernel-debuginfo
- kernel-debuginfo-common
- kernel-devel

一定要安装与当前内核版本一致的包。当前环境的内核版本是3.10.0-693.2.2.el7.x86_64，所以需要安装的包为：

- kernel-debuginfo-3.10.0-693.2.2.el7.x86_64
- kernel-debuginfo-common-3.10.0-693.2.2.el7.x86_64
- kernel-devel-3.10.0-693.2.2.el7.x86_64

==注意不要直接yum install kernel-debuginfo kernel-debuginfo-common kernel-devel, 即使能找到相应的包，也是安装的最新版本，不会自动匹配当前版本。所以我们下载RPM包，再用rpm命令依次安装。==

对于CentOS来说，内核符号文件一版在http://debuginfo.centos.org上有各个版本非常完整的包，但是一般从境内下载都比较慢，特别是kernel-debuginfo，比较大下载可能非常慢。所以在debuginfo.centos.org上下了kernel-debuginfo-common包，另外两个包在Google上搜了一把，分别找了两个镜像。下了之后才发现这个地方有坑，这个坑在后面展开讲。

```bash
wget https://ftp.sjtu.edu.cn/scientific/7/archive/debuginfo/kernel-debuginfo-3.10.0-693.2.2.el7.x86_64.rpm
wget http://debuginfo.centos.org/7/x86_64/kernel-debuginfo-common-x86_64-3.10.0-693.2.2.el7.x86_64.rpm
wget ftp://mirror.switch.ch/pool/4/mirror/scientificlinux/7.0/x86_64/updates/security/kernel-devel-3.10.0-693.2.2.el7.x86_64.rpm
```
```bash
# rpm -ivh kernel-debuginfo-common-x86_64-3.10.0-693.2.2.el7.x86_64.rpm
# rpm -ivh kernel-debuginfo-3.10.0-693.2.2.el7.x86_64.rpm
# rpm -ivh kernel-devel-3.10.0-693.2.2.el7.x86_64.rpm
```
test
```bash
# stap -e 'probe begin{printf("Hello, World"); exit();}'
```

#### Checking "/lib/modules/2.6.32-431.el6.x86_64/build/.config" failed with error: 没有那个文件或目录

rpm -ql kernel-devel 看看安装到哪里了，如果是 /usr/src/kernels/2.6.32-431.el6.x86_64 那么不妨执行：
```
ln -s /usr/src/kernels/2.6.32-431.el6.x86_64 /lib/modules/2.6.32-431.el6.x86_64/build

```



#### 解决"ERROR: module version mismatch"问题

解决问题的另一个简单方法就是直接修改这个compile.h文件，原来的文件如下：
```bash
# cat /usr/src/kernels/3.10.0-693.2.2.el7.x86_64/include/generated/compile.h
/* This file is auto generated, version 1 */
/* SMP */
#define UTS_MACHINE "x86_64"
#define UTS_VERSION "#1 SMP Tue Sep 12 10:10:26 CDT 2017"
#define LINUX_COMPILE_BY "mockbuild"
#define LINUX_COMPILE_HOST "sl7-uefisign.fnal.gov"
#define LINUX_COMPILER "gcc version 4.8.5 20150623 (Red Hat 4.8.5-16) (GCC) "
```
修改define UTS_VERSION那一行，如下：

```bash
#define UTS_VERSION "#1 SMP Tue Sep 12 10:10:26 CDT 2017" -> #define UTS_VERSION "#1 SMP Tue Sep 12 22:26:13 UTC 2017"
```

再次运行stap:

```bash
# stap -e 'probe begin{printf("Hello, World"); exit();}' -v
Pass 1: parsed user script and 470 library scripts using 228220virt/41276res/3348shr/38016data kb, in 350usr/10sys/355real ms.
Pass 2: analyzed script: 1 probe, 1 function, 0 embeds, 0 globals using 229144virt/42328res/3536shr/38940data kb, in 0usr/0sys/6real ms.
Pass 3: using cached /root/.systemtap/cache/0b/stap_0bc9e27aef7a1de50ea41889a27fc524_1010.c
Pass 4: using cached /root/.systemtap/cache/0b/stap_0bc9e27aef7a1de50ea41889a27fc524_1010.ko
Pass 5: starting run.
ERROR: module version mismatch (#1 SMP Tue Sep 12 10:10:26 CDT 2017 vs #1 SMP Tue Sep 12 22:26:13 UTC 2017), release 3.10.0-693.2.2.el7.x86_64
WARNING: /usr/bin/staprun exited with status: 1
Pass 5: run completed in 0usr/10sys/38real ms.
Pass 5: run failed.  [man error::pass5]
```

因为中间生成的C文件和ko模块都是用的cache (蓝色标注的部分)，我们把上面的cache文件删除，再重新运行，这次可以成功了。

```bash
# stap -e 'probe begin{printf("Hello, World"); exit();}'
Hello, World
```

#### 参考
https://sourceware.org/systemtap/SystemTap_Beginners_Guide/using-systemtap.html#using-setup

https://blog.csdn.net/yunlianglinfeng/article/details/77732285

https://groups.google.com/forum/#!topic/openresty/nlEc3qlDyOc