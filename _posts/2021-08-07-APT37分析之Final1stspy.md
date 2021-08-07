---
layout: post
title: APT37分析之Final1stspy
excerpt: "先知社区投稿"
categories: [先知社区投稿]
comments: true
---

### 样本分析

| 样本名称 | Final1stspy,Dropper                                          |
| -------- | ------------------------------------------------------------ |
| 样本类型 | PE32 executable (DLL) (GUI) Intel 80386, for MS Windows      |
| 样本大小 | 244224                                                       |
| MD5      | 0dd50c4a5aa9899504cb4cf95acd981e                             |
| SHA1     | 38f28bfce4d0b2b497e6cf568d08a2b6af244653                     |
| SHA256   | 2011b9aa61d280ca9397398434af94ec26ddb6ab51f5db269f1799b46cf65a76 |

### 线上沙箱

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320102803-6ce43e9a-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320102803-6ce43e9a-6a52-1.png)

### 动静态分析

查看导入表,看到反调试相关的函数

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320102858-8de178ba-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320102858-8de178ba-6a52-1.png)

程序中多次使用IsDebuggerPresent来检测程序是否被调试

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320102951-ad77b05e-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320102951-ad77b05e-6a52-1.png)

或使用GetStartupInfo检测程序是否正在被调试

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103027-c2df4f10-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103027-c2df4f10-6a52-1.png)

查看加密方式,发现样本采用base64编码和sha1哈希算法

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103048-cf5a11ee-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103048-cf5a11ee-6a52-1.png)
查看样本导出表,看到只有一个main_func

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103104-d8e2f0b4-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103104-d8e2f0b4-6a52-1.png)
进入main_func看到3个线程相关的函数

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103123-e465efae-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103123-e465efae-6a52-1.png)
进入核心函数看到样本采用运行时加载dll的方法,绕过基于导入表的检测

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103149-f3abec70-6a52-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103149-f3abec70-6a52-1.png)

##### com组件执行恶意操作

在9e0函数中继续跟进ea0函数,发现该样本使用com组件执行操作,通过CoCreateInstance创建组件

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103211-0100619e-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103211-0100619e-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103225-08d60e5a-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103225-08d60e5a-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103240-12209674-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103240-12209674-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103257-1c194964-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103257-1c194964-6a53-1.png)
我们通过样本中的rclsid和riid参数查询出代码所运行的函数

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103323-2b9c4a62-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103323-2b9c4a62-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103334-325e2fdc-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103334-325e2fdc-6a53-1.png)
并在注册表中进行查询

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103356-3f3a19d2-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103356-3f3a19d2-6a53-1.png)
dc12a687-737f-11cf-884d-00aa004b2e24这个是调用WMI相关

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103413-492d4680-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103413-492d4680-6a53-1.png)
之后样本通过ppv的偏移执行了对应的函数,如下执行了ConnectServer

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103434-55c08bb4-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103434-55c08bb4-6a53-1.png)

随后调用ExecQuery执行WMI查询

##### 持久化

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103456-6328d2d4-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103456-6328d2d4-6a53-1.png)
跳出9e0函数,跟进c30,动态调试发现该函数为解密函数
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103602-8a6a6042-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103602-8a6a6042-6a53-1.png)
将解密得到的'rundll32'作为参数,传入1460函数,该函数使用LoadLibrary和GetProcAddress找到控制注册表的函数地址,在SOFTWARE\Microsoft\Windows\CurrentVersion\Run写入自启动时间持久化
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103621-95913e00-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103621-95913e00-6a53-1.png)
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103639-a050471e-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103639-a050471e-6a53-1.png)

##### 反监控

跟进18d0函数,程序中使用进程枚举,并通过与解密字串名称匹配的方法,来检测是否有特定进行
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103701-ad76f3fc-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103701-ad76f3fc-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103740-c4c7c388-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103740-c4c7c388-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103803-d2c0b54e-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103803-d2c0b54e-6a53-1.png)
通过动态调试,发现加密的字符串解密后如下

```
Ollydbg.exe
idaq.exe
gmer.exe
IceSword.exe
wireshark.exe
tcpview.exe
procexp.exe
peview.exe
cff explorer.exe
```

若进程中发现有这些进程,则关闭该进程,并返回1,继续进入anti_debug4,直到进程中没有wireshark等监控程序的存在

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103821-dd3f607e-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103821-dd3f607e-6a53-1.png)

##### 发送请求

首先使用解密函数将域名及表头特征信息解密,然后传入参数中进行请求发送

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103837-e6fe1380-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103837-e6fe1380-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103850-ee5fc86c-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103850-ee5fc86c-6a53-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103905-f79a93da-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103905-f79a93da-6a53-1.png)

进入该函数,同样是运行后动态寻址

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103917-fe63d88e-6a53-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103917-fe63d88e-6a53-1.png)
请求返回值200才正常运行,否则退出

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103934-08bb3c78-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103934-08bb3c78-6a54-1.png)

读取信息,仅当response开头是`selfsign`的时候跳出循环

拦截dns并在本地设置监听,本机接收到病毒发来的请求
[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320103949-119be25c-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320103949-119be25c-6a54-1.png)

##### 进程替换技术

将response包内容读取之后,进入20a0函数,该函数同样通过LoadLibrary和GetProcAddress在运行后得到函数地址

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104004-1ab1ba4c-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104004-1ab1ba4c-6a54-1.png)

经分析后发现该函数为进程替换函数,具体步骤为:首先创建一个正常的进程,VirtualAllocEx为恶意代码分配新的内存,WriteProcessMemory将恶意代码写入内存,SetThreadContext指向恶意代码,ResumeThread让恶意代码执行

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104018-22e96b88-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104018-22e96b88-6a54-1.png)

### 关联分析

通过样本暴漏的pdb路径的搜索,搜索到相关信息

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104044-32474500-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104044-32474500-6a54-1.png)

通过代码复用和特殊字段的匹配的方式,匹配到了该病毒属Final1stspy家族

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104102-3d2c9e02-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104102-3d2c9e02-6a54-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104113-43ad9902-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104113-43ad9902-6a54-1.png)

对该域名关联的其他文件进行代码复用和特殊字符匹配,同样匹配到了Final1stspy家族

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104125-4af711ac-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104125-4af711ac-6a54-1.png)

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104135-50d0607e-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104135-50d0607e-6a54-1.png)

进而继续查找Final1stspy的信息

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104145-56991406-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104145-56991406-6a54-1.png)

进而查找dogcall

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200320104154-5c1f73ac-6a54-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200320104154-5c1f73ac-6a54-1.png)

### IOCS

Hash: 2011b9aa61d280ca9397398434af94ec26ddb6ab51f5db269f1799b46cf65a76

Domain: kmbr1[.]nitesbr1[.]org

Url: http[:]//kmbr1[.]nitesbr1[.]org/UserFiles/File/image/index.php

##### ATT&CK ID:

T1060 - Registry Run Keys / Startup Folder
T1047 - Windows Management Instrumentation
T1087 - Account Discovery
T1055 - Process Injection
T1085 - Rundll32
T1175 - Component Object Model and Distributed COM
T1022 - Data Encrypted
T1057 - Process Discovery

