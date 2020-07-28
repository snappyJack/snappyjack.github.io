---
layout: post
title: pwn plaidctf2015 plaiddb
excerpt: "plaidctf plaiddb writeup"
categories: [未完待续]
comments: true
---

PUT,DEL有malloc和free,RB-tree中没有对heap的操作

ida反编译之后的漏洞代码
```c
__int64 main_loop()
{
  __int64 cmd; // [sp+0h] [bp-18h]@1
  __int64 v2; // [sp+8h] [bp-10h]@1

  v2 = *MK_FP(__FS__, 40LL);
  puts("PROMPT: Enter command:");
  readn((char *)&cmd, 8LL);
  if ( !memcmp(&cmd, "GET\n", 5uLL) )
  {
    sub_1170();
  }
  else if ( !memcmp(&cmd, "PUT\n", 5uLL) )
  {
    do_PUT();
  }
  else if ( !memcmp(&cmd, "DUMP\n", 6uLL) )
  {
    do_DUMP();
  }
  else if ( !memcmp(&cmd, "DEL\n", 5uLL) )
  {
    do_DEL();
  }
  else
  {
    if ( !memcmp(&cmd, "EXIT\n", 6uLL) )
      goodbye();
    __printf_chk(1LL, "ERROR: '%s' is not a valid command.\n", &cmd);
  }
  return *MK_FP(__FS__, 40LL) ^ v2;
}
```
通过fuzz得到的payload如下
```
PUT


PUT


GET
000000000000000000000000
```
看到一个小时整