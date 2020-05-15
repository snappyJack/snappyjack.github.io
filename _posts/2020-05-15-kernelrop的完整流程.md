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
mov %rax,%rdi;ret
addr of commit_creds()
...
```

