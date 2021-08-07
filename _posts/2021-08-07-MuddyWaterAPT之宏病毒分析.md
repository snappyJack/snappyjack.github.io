---
layout: post
title: MuddyWaterAPT之宏病毒分析
excerpt: "先知社区投稿"
categories: [先知社区投稿]
comments: true
---

### 一、样本IOC指标

| 样本名   | NETA_-T_bitak Siber G_venlik **birli_i Protokol**v5.doc      |
| -------- | ------------------------------------------------------------ |
| Md5      | 21aebece73549b3c4355a6060df410e9                             |
| Sha1     | dbab599d65a65976e68764b421320ab5af60236f                     |
| 样本大小 | 314368 bytes                                                 |
| 样本类型 | Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.1, Code page: 1252, Template: Normal.dotm, Last Saved By: Babak Amiri, Revision Number: 240, Name of Creating Application: Microsoft Office Word, Total Editing Time: 12:01:00, Create Time/Date: Mon Feb 18 06:17:00 2019, Last Saved Time/Date: Thu Feb 28 18:20:00 2019, Number of Pages: 1, Number of Words: 296, Number of Characters: 1691, Security: 0 |

### 二、线上沙箱


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_1.png)


### 三、样本分析:
打开文件,查看宏代码发现已加密


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_2.png)

使用工具将密码删除


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_3.png)

再次打开doc,发现加密的宏代码


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_4.png)

同时在窗体中发现部分嵌入的代码


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_5.png)

通过属性找到对应的代码,如Form1中


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_6.png)

Form2


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_7.png)

宏代码在自启动文件夹下创建`Win32ApiSyncTskSchdlr.bat`,并写入`start /MIN schtasks /Create /F /SC HOURLY /MO 1 /TN Win32ApiSyncTask /TR "C:\ProgramData\Win32ApiSync.bat"`


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_8.png)



![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_9.png)



![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_10.png)

同时创建`C:\ProgramData\Win32ApiSync.bat`,并写入一段powershell代码


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_11.png)



![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_12.png)

写入的内容为

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_13.png)

该代码做了如下3件事
1. 获取Win32ApiSyncLog.txt中的内容
2. 将内容进行解码
3. 运行解码后的内容

同时创建C:\ProgramData\Win32ApiSyncLog.txt,并将宏代码中的ep内容写入到文件中

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_14.png)



![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_15.png)

至此该病毒流程分析完毕,流程图如下


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_16.png)

下面对Win32ApiSyncLog.txt内容进行解密,首先使用base64将ep解码,发现解码后的内容为嵌套powershell代码


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_17.png)

使用如下代码将powershell中FromBase64String中的内容转换为string


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_18.png)


```python
import base64
import zlib

# [Convert]::FromBase64String
decoded = base64.b64decode(encoded)

# IO.Compression.DeflateStream
# 15 is the default parameter, negative makes it ignore the gzip header
decompressed = zlib.decompress(decoded, -15)
print(str(decompressed, encoding = "utf-8").lower())
```

运行后得到混淆的powershell代码


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_19.png)

使用https://github.com/pan-unit42/public_tools/tree/master/powershellprofiler 中的脚本对代码进行初步反混淆,然后再手动调整代码,还原的powershell代码如下

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_20.png)

### 二、后门分析：
首先是main函数,while循环下分别运行了三个函数helloserverloop, getcommandloop和executecommandandsetcommandresultloop

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_21.png)

对于helloserverloop函数,该函数循环向c2发送请求,调用了helloserverrequest函数

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_22.png)

跟进helloserverrequest如下,函数调用了assembler,并为请求设置了代理

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_23.png)

跟进assembler函数如下,该函数调用了getbasicinfo函数,又继而调用了basicinfocollector函数

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_24.png)



![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_25.png)

继续跟进basicinfocollector函数,该海曙为基础信息收集函数,收集了用户名,系统版本,内网地址能信息

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_26.png)

接下来我们分析getcommandloop函数,该函数循环向c2发送请求,并将response包解析,结果保存到全局变量getcmdresult中


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_27.png)

我们继续分析executecommandandsetcommandresultloop函数,若全局变量getcmdresult为空,改函数则运行` ping -n 1 127.0.0.1`指令,否则就运行getcmdresult变量中的指令,并将结果保存并使用base64编码,最后将结果发送到c2中

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_28.png)


![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_29.png)

### 四、查杀建议：
经分析该后门并没有高深的隐藏技术,分别删除启动项,计划任务,源文件即可

删除启动项中的文件

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_30.png)

删除计划任务

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_31.png)

删除病毒源文件

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/xz_26.png)
