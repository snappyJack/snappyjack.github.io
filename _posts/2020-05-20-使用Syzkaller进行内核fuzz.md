---
layout: post
title: 使用Syzkaller进行内核fuzz
excerpt: "内核Fuzz"
categories: [知识总结]
comments: true
---
文章主要参考:https://i-m.dev/posts/20200313-143737.html ,亲测可用,做个总结

#### 安装go
syzkaller使用go语言编写,运行syzkaller要安装go,如下
```
wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar -xf go1.14.2.linux-amd64.tar.gz
mv go goroot
mkdir gopath
export GOPATH=`pwd`/gopath
export GOROOT=`pwd`/goroot
export PATH=$GOPATH/bin:$PATH
export PATH=$GOROOT/bin:$PATH
```
#### 安装Syzkaller
然后下载和编译syzkaller,如下
```
go get -u -d github.com/google/syzkaller/prog
cd gopath/src/github.com/google/syzkaller/
make
```
之后我们就可以在`bin/`目录下看到编译的二进制文件了
#### 安装qemu-kvm
```
sudo apt install qemu-kvm
sudo usermod -aG kvm $USER
```
kvm功能可以让QEMU执行得更快，同时为了让启用kvm支持不需要root权限，需要将当前用户添加到kvm组中去，完成后注销登陆即可。
#### 制作系统镜像
Syzkaller虽然是对内核进行测试，但是内核一个光杆司令是没办法用的，所以需要制作一个系统镜像，其中需要提供ssh、gcc等工作环境.偷懒的方法是使用Syzkaller官方提供的脚本：
```
# 安装debootstrap
sudo apt install debootstrap
# 下载脚本
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
# 添加可执行权限
chmod +x create-image.sh
# 使用清华源，不然慢死了
sed -i -e 's~sudo debootstrap .*~\0 https://mirrors.tuna.tsinghua.edu.cn/debian/~' create-image.sh
# 制作镜像，1024MB
./create-image.sh -s 1024
```
其脚本大致的操作为：

- 基于debian stretch并添加openssh-server、curl、tar等软件包，在当前目录下创建了一个chroot系统目录
- 将镜像系统的root用户密码设置为空、生成ssh密钥对并添加之，更改了一些必要的系统选项
- 将该目录写入到一个ext4格式的镜像文件中去，即./stretch.img文件

#### 编译支持syzkaller的内核
下载内核
```
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.0.tar.gz
tar -xvf linux-5.0.tar.gz
```
配置
```
cd linux-5.0
# 先采用默认配置
make defconfig
# 启用kvm
make kvmconfig
# Syzkaller需要启用一些调试功能
echo '
CONFIG_KCOV=y
CONFIG_DEBUG_INFO=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y' >> .config
# 再次对新引入的配置采用默认值
make olddefconfig
```
为了进行测试,修改`fs/open.c`代码
```
diff --git a/fs/open.c b/fs/open.c
index 0285ce7db..3ab215a93 100644
--- a/fs/open.c
+++ b/fs/open.c
@@ -523,6 +523,12 @@ SYSCALL_DEFINE1(chroot, const char __user *, filename)
 
 static int chmod_common(const struct path *path, umode_t mode)
 {
+    static umode_t old_mode = 0xffff;
+    if (old_mode == 0 && mode == 0) {
+        path = NULL;
+    }
+    old_mode = mode;
+
        struct inode *inode = path->dentry->d_inode;
        struct inode *delegated_inode = NULL;
        struct iattr newattrs;
```
编译bzImage
```
make bzImage
```
#### 尝试虚拟机启动
```
qemu-system-x86_64 -m 1G -enable-kvm -drive file=/root/stretch.img,format=raw -kernel /root/linux-5.0/arch/x86/boot/bzImage -append "root=/dev/sda console=ttyS0" -nographic
```
正常的话，会进入TTY（，显示界面可能会有旧输出的残留，仔细看），用户root，密码为空，就可以使用这个系统了。
```
root@syzkaller:~# uname -a
Linux syzkaller 5.0.0 #1 SMP Wed May 20 12:46:34 CST 2020 x86_64 GNU/Linux
```
#### 配置config.json
```
{
    "target": "linux/amd64",
    "http": "0.0.0.0:8080",
    "workdir": "/root/gopath/src/github.com/google/syzkaller/bin/workdir",
    "kernel_obj": "/root/linux-5.0/vmlinux",
    "image": "/root/stretch.img",
    "sshkey": "/root/stretch.id_rsa",
    "syzkaller": "/root/gopath/src/github.com/google/syzkaller",
    "enable_syscalls": ["chmod"],
    "procs": 1,
    "type": "qemu",
    "vm": {
        "count": 1,
        "kernel": "/root/linux-5.0/arch/x86/boot/bzImage",
        "cpu": 1,
        "mem": 1024
    }
}
```
enable_syscalls设置为`["chmod"]`，表示只对chmod调用进行测试。
#### 执行测试
```
./syz-manager --config config.json
```
输出如下
```
root@snappyjack-VirtualBox:~/gopath/src/github.com/google/syzkaller/bin# ./syz-manager --config config.json
2020/05/20 14:55:54 loading corpus...
2020/05/20 14:55:54 serving http on http://0.0.0.0:8080
2020/05/20 14:55:54 serving rpc on tcp://[::]:38349
2020/05/20 14:55:54 booting test machines...
2020/05/20 14:55:54 wait for the connection from test machine...
2020/05/20 14:56:16 machine check:
2020/05/20 14:56:16 syscalls                : 1/3361
2020/05/20 14:56:16 code coverage           : enabled
2020/05/20 14:56:16 comparison tracing      : CONFIG_KCOV_ENABLE_COMPARISONS is not enabled
2020/05/20 14:56:16 extra coverage          : extra coverage is not supported by the kernel
2020/05/20 14:56:16 setuid sandbox          : enabled
2020/05/20 14:56:16 namespace sandbox       : /proc/self/ns/user does not exist
2020/05/20 14:56:16 Android sandbox         : enabled
2020/05/20 14:56:16 fault injection         : CONFIG_FAULT_INJECTION is not enabled
2020/05/20 14:56:16 leak checking           : CONFIG_DEBUG_KMEMLEAK is not enabled
2020/05/20 14:56:16 net packet injection    : /dev/net/tun does not exist
2020/05/20 14:56:16 net device setup        : enabled
2020/05/20 14:56:16 concurrency sanitizer   : /sys/kernel/debug/kcsan does not exist
2020/05/20 14:56:16 devlink PCI setup       : PCI device 0000:00:10.0 is not available
2020/05/20 14:56:16 USB emulation           : /dev/raw-gadget does not exist
2020/05/20 14:56:16 corpus                  : 6 (deleted 0 broken, 0 too long)
2020/05/20 14:56:24 VMs 1, executed 55, cover 440, crashes 0, repro 0
2020/05/20 14:56:34 VMs 1, executed 55, cover 545, crashes 0, repro 0
2020/05/20 14:56:44 VMs 1, executed 333, cover 545, crashes 0, repro 0
2020/05/20 14:56:48 vm-0: crash: general protection fault in chmod_common
2020/05/20 14:56:48 reproducing crash 'general protection fault in chmod_common': 367 programs, 1 VMs, timeouts [15s 1m0s 6m0s]
2020/05/20 14:56:54 VMs 0, executed 333, cover 545, crashes 1, repro 1
```
fuzz正式工作