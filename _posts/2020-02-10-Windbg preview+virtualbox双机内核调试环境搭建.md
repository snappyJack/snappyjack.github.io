---
layout: post
title: Windbg preview+virtualbox双机内核调试环境搭建
excerpt: "内核调试"
categories: [知识总结]
comments: true
---
##### 宿主机:win10 目标机:win7
在目标机中运行`msconfig`,然后进行如下配置
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/宿主机配置.png)
然后
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/宿主机配置2.png)
在WinDbg pewview中打开`文件`,然后进行如下操作
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/windbgpreview配置.png)
在virtualbox中进行如下配置
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/virtualbox配置.png)
至此环境搭建完成,调试的时候先运行好虚拟机,然后再运行windbg preview就行
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/运行画面.png)

### windbg出现SYMSRV:  HttpSendRequest: 800C2EFD - ERROR_INTERNET_CANNOT_CONNECT这个问题
走外网代理就能成功,设置`set _NT_SYMBOL_PROXY=127.0.0.1:8080`,成功解决

根本原因是下载的时候,下载地址进行了302跳转,跳到了这个域名vsblobprodscussu5shard10.blob.core.windows.net,而这是不fanqiang无法访问的,所以导致了下载失败