---
layout: post
title: 基于Mitmproxy实现的多终端全网流量监控 
excerpt: "完整代码地址： https://github.com/snappyJack/mitmdump_monitor/blob/master/mitmdump_monitor.py"
categories: [netflow]
comments: true
---
> Mitmproxy是一个python编写的代理工具,该工具可完成http/https、tcp消息、websocket的提取与存储， 达到漏洞挖掘、信息监控的目的。Mitmproxy项目地址：https://mitmproxy.org/

### 电脑端证书的安装

下载项目并运行mitmweb.exe

设置浏览器代理ip:8080并访问http://mitm.it/

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(1).png)

按照该网页中的说明进行根证书安装

### 手机端证书的安装
1. 设置http代理
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(2).png)
2. 手机端访问http://mitm.it/ ，并下载相应证书
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(3).jpg)
3.	在设置中安装证书
4.	信任该证书
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(4).png)

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(5).png)

### 非浏览器流量抓取
Proxifier设置全局http代理，指向代理地址

Proxifier下载地址：https://www.proxifier.com

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(6).png)

### 安卓设备中的证书导入与全局代理设置
设备连接：
```
adb connect x.x.x.x:5555
```
证书的导入：
```
adb push xxx(本地证书地址) xxxx(安卓设备中地址)
```
添加证书的信任：
```
adb shell am start -n com.android.certinstaller/.CertInstallerMain -a android.intent.action.VIEW -t application/x-x509-ca-cert file:///sdcard/burp.cer   (file:///sdcard/burp.cer为证书地址)
```
全局代理的设置：
```
adb shell settings put global http_proxy x.x.x.x:8080
```
### 流量的持久化存储
将http/https流量存储到mongodb中：
实现代码地址：https://discourse.mitmproxy.org/t/har-mongo-dump-script/901

Mongodb中的结果：
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(7).png)

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(8).png)

依葫芦画瓢，添加websocket存储：

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(9).png)

Mongodb中的结果：

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(10).png)

继续添加tcp_message存储：

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/mitmproxy(11).png)

暂未抓到tcp消息的流量。。


修改后的完整代码地址：
https://github.com/snappyJack/mitmdump_monitor/blob/master/mitmdump_monitor.py
