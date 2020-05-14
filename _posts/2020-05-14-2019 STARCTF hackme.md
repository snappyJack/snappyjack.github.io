---
layout: post
title: 2019 STARCTF hackme
excerpt: "kernel pwn"
categories: [未完待续]
comments: true
---
参考:https://xz.aliyun.com/t/6067
#### modprobe_path
modprobe_path指向了一个内核在运行未知文件类型时运行的二进制文件;当内核运行一个错误格式的文件的时候,会调用这个modprobe_path所指向的二进制文件去，如果我们将这个字符串指向我们的自己的二进制文件,那么在发生错误的时候就可以执行我们自己二进制文件了....

查看modprobe_path地址
```
root@snappyjack:~/2019# cat /proc/kallsyms | grep modprobe_path
ffffffffa405bce0 D modprobe_path
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

##### 总结:就是通过任意地址读写修改modprobe_path处的二进制文件,从而进行任意文件读写