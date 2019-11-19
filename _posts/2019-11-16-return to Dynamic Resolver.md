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