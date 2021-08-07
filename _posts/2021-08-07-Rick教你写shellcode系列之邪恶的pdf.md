---
layout: post
title: Rick教你写shellcode系列之邪恶的pdf
excerpt: "先知社区投稿"
categories: [先知社区投稿]
comments: true
---



#### 起因

exploit-db中一篇关于PDFResurrect的溢出引起了我的注意:

> PDFResurrect 0.15 has a buffer overflow via a crafted PDF file because data associated with startxref and %%EOF is mishandled.(https://www.exploit-db.com/exploits/47178)

该软件在解析pdf的时候对于startxref错误的控制导致了栈溢出(CVE-2019-14267).

既然都栈溢出了,理论上我们是可以在pdf中写入构造好的payload,实现getshell的,然而在type一栏中作者确只写了DoS,pyaload样本也只是一个导致DoS的crash样本.那么我们来试一下在pdf中写入payload

#### 下载和编译

安装的过程比较简单,`./configure`之后,修改MakeFile中的CFLAGS如下

```
CFLAGS = -O0 -g -Wall -fno-stack-protector $(EXTRA_CFLAGS)
-O0`关掉优化方便gdb调试,而单一的stack overflow,让我们`-fno-stack-protector
```

make之后查看下保护状态
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424123625-2809eb68-85e5-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424123625-2809eb68-85e5-1.png)

#### 开始尝试

根据漏洞的类型和文件的保护措施,第一想到的就是使用ROP绕过NX,从而实现getshell.然而在pdfresurrect不存在system()这种功能,在里面找rop链是基本没戏了,只能从动态链接库中找找看

所以是时候祭出我们的神器了,one_gadget:一键查找可用的rop链 https://github.com/david942j/one_gadget
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424123940-9c832b08-85e5-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424123940-9c832b08-85e5-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124024-b66b7dcc-85e5-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124024-b66b7dcc-85e5-1.png)
找到了4条rop链,具体用哪条,到最后的一步再看.

##### offset的计算

根据作者提供的信息,溢出出现的位置如下

```
...
...
char x, *c, buf[256];
...
...
    for (i=0; i<pdf->n_xrefs; i++)
    {
        /* Seek to %%EOF */
        if ((pos = get_next_eof(fp)) < 0)
          break;

        /* Set and increment the version */
        pdf->xrefs[i].version = ver++;

        /* Rewind until we find end of "startxref" */
        pos_count = 0;
        while (SAFE_F(fp, ((x = fgetc(fp)) != 'f'))) <== The loop will continue incrementing pos_count until find a 'f' char
          fseek(fp, pos - (++pos_count), SEEK_SET);

        /* Suck in end of "startxref" to start of %%EOF */
        memset(buf, 0, sizeof(buf));
        SAFE_E(fread(buf, 1, pos_count, fp), pos_count, <== If pos_count > 256 then a buffer overflow occur
               "Failed to read startxref.\n");
        c = buf;
        while (*c == ' ' || *c == '\n' || *c == '\r')
          ++c;

        /* xref start position */
        pdf->xrefs[i].start = atol(c);
...
...
```

我们在pdf.c:237处打一个断点,并分别查找buf和rbp的位置,从而计算payload需要的偏移
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124154-ec473454-85e5-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124154-ec473454-85e5-1.png)

如图所示,buf位置`0x7fffffffe460`,rbp位置`0x7fffffffe5a0`,所以我们的offset为

```
offset=0x5a0-0x460 = 320
```

我们使用notepad打开pdf,添加在`xref`和`%%EOF`中添加offset如下
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124249-0ce58d32-85e6-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124249-0ce58d32-85e6-1.png)
然后我们使用gdb调试,运行完fread函数之后栈空间情况如下
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124355-3455ef9c-85e6-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124355-3455ef9c-85e6-1.png)
正如我们所愿,刚好覆盖到rbp前一个位置

##### 遇见第一个坑

继续往下走,在`0x40217b`出现了问题,指令对比`rdx`与`rax`,若不等,程序退出,幸好我们的rax可控,此处修改至相等即可绕过.
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124518-6605a532-85e6-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124518-6605a532-85e6-1.png)

##### 遇见第二个坑

运行到`0x4021db`出现了第二个问题
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124618-8994de3c-85e6-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124618-8994de3c-85e6-1.png)
stack上的覆盖影响到了`pdf->xrefs[i]`中i的值,出现了报错,导致程序crash,仔细查看i的值,发现同样可控,在没有仔细研究源码的情况下,同样的无脑修改使其绕过.

##### 风雨之后并没有见彩虹

绕过了前两个,迎来了第三个
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124712-a9cc144a-85e6-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124712-a9cc144a-85e6-1.png)
此处是一个正常退出,这就需要研究一下源码
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424124929-fb4a186c-85e6-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424124929-fb4a186c-85e6-1.png)
程序退出的位置在is_valid_xref函数的587行,巨大的`xref->start`使文件指针指向了一个非常靠后的位置,结果可想而知,文件内容读取失败.

而奇怪的`0x2bdc528094fb87`数值让人摸不到头脑,貌似是一个不可控的数值,从哪里来的不知道.就在我准备放弃的时候,条件反射查了一下数值
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424125011-14aa8e40-85e7-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424125011-14aa8e40-85e7-1.png)
damn!又是可控!只好继续无脑修改

##### 黎明的曙光就在眼前

通过proc查看libc基地址然后计算出rop实际地址
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424131438-7ebd9cc0-85ea-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424131438-7ebd9cc0-85ea-1.png)
终于见到了大boss,即将ret到rop地址
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424125131-43f0b328-85e7-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424125131-43f0b328-85e7-1.png)
可现实却给了我当头一棒
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424125227-658de186-85e7-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424125227-658de186-85e7-1.png)

没有one_gadget符合的条件!what else can I do?

##### 没有条件创造条件

没有符合的条件,只好硬着头皮查找其他gadget

```
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6
```

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424125346-946abcc2-85e7-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424125346-946abcc2-85e7-1.png)

##### 终于找到你,还好我没放弃

利用两个`sub rax, 1 ; ret`让rax置零,再接那个rax == NULL的one_gadget,winhex中修改
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424125438-b3529b14-85e7-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424125438-b3529b14-85e7-1.png)
测试
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200424125521-cd42e9ac-85e7-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200424125521-cd42e9ac-85e7-1.png)
boom!!成功拿到shell,大功告成!

#### 附件

完整的payload见 https://github.com/snappyJack/pdfresurrect_CVE-2019-14267
其中rop位置可能需要自行修改

本人gcc和系统版本如下

```
root@c7c87f16a29d:/home/pdfresurrect-0.15# /lib/x86_64-linux-gnu/libc.so.6 -V
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.4.0 20160609.
Available extensions:
    crypt add-on version 2.1 by Michael Glad and others
    GNU Libidn by Simon Josefsson
    Native POSIX Threads Library by Ulrich Drepper et al
    BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
root@c7c87f16a29d:/home/pdfresurrect-0.15# uname -a
Linux c7c87f16a29d 3.10.0-1062.4.1.el7.x86_64 #1 SMP Fri Oct 18 17:15:30 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
root@c7c87f16a29d:/home/pdfresurrect-0.15#
```

#### 参考

https://www.exploit-db.com/exploits/47178