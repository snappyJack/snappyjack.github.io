---
layout: post
title: Domain Fronting配置手册
excerpt: "Domain Fronting"
categories: [Redteam]
comments: true
---

#### 首先进入aws后台(`https://console.aws.amazon.com/console/home?region=us-east-1`)并选择CloudFronting服务

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/domain_front1.png)

#### 点击创建分配并选择web
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/domain_front2.png)
#### 进行如下配置
![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/domain_front3.png)

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/domain_front4.png)
#### 进行验证
```
[root@localhost html]# curl http://snappyzz.com/test.html
snappyjack
[root@localhost html]# curl http://d36niw3noxy6zx.cloudfront.net/test.html
snappyjack

```

#### 采用host头
```
[root@localhost html]# curl http://a0.awsstatic.com/test.html --header "Host: d36niw3noxy6zx.cloudfront.net"
snappyjack
```
#### 查找高信誉域名
```
for i in {a..z}; do for j in {0..9}; do wget -U demo -q -O - http://$i$j.awsstatic.com/test.html --header "Host: d36niw3noxy6zx.cloudfront.net" && echo $i$j; done;done
```
结果
```
[root@localhost html]# for i in {a..z}; do for j in {0..9}; do wget -U demo -q -O - http://$i$j.awsstatic.com/test.html --header "Host: d36niw3noxy6zx.cloudfront.net" && echo $i$j; done;done
snappyjack
a0
snappyjack
a1
snappyjack
d0
snappyjack
d1
snappyjack
f0
snappyjack
l0
snappyjack
r0
snappyjack
s0

```
当然这里还可以写一个脚本来从热门网站列表中寻找可以使用的CDN子域，关于这个可以参考这个文章:https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/