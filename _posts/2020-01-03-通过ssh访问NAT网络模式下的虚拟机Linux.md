---
layout: post
title: 通过ssh访问NAT网络模式下的Linux虚拟机
excerpt: "通过ssh访问NAT网络模式下的Linux虚拟机"
categories: [知识总结]
comments: true
---

NAT模式在VMware下又称VMnet8。在这种模式下，宿主机有两块网卡，一块是真实的物理网卡（即NAT device），连接Network；一块是 VMware Network Adapter VMnet8，通过虚拟交换机（VMnet8）与虚拟机网卡进行通信。

由于NAT device有网络地址转换功能，虚拟机网卡的数据通过 VMware Network Adapter VMnet8转发，进行地址转换后，由真实的物理网卡再转发到NetWork。此外，在NAT模式下，宿主计算机相当于一台开启了DHCP功能的路由器，而虚拟机则是内网中的一台真实主机，通过路由器(宿主计算机)DHCP动态获得网络参数。因此在NAT模式下，虚拟机可以访问外部网络，反之则不行[1]（注：如果我们在VMware下做了NAT设置，则可以实现从外部网络访问虚拟机，下文将会讲述）。


#### 主机在virtualbox在NAT方式SSH访问
1. 首先查看virtualbox网卡的ip
2. 在NAT网络设置中的'端口转发'中,配置主机ip为virtualbox网卡的ip,子ip为虚拟机中的ip,主机端口和子系统端口按自己的需求来设置