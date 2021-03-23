---
layout: post
title: falco与sysdig试用
excerpt: "工具试用"
categories: [知识总结]
comments: true
---



### 关于 Falco 

Falco 是一款旨在检测应用中反常活动的行为监视器，由[Sysdig](https://github.com/draios/sysdig)的[系统调用捕获](https://sysdig.com/blog/fascinating-world-linux-system-calls/)基础设施驱动。您仅需为 Falco 撰写[一套规则](https://falco.org/docs/rules)，即可在一处持续监测并监控容器、应用、主机及网络的异常活动。

### 监控软件的分类

Seccomp, seccomp-bpf, SELinux, 和 AppArmor 是通过制定规则来改变程序的运行状态

Falco和Audit是通过制定规则来监控程序的运行状态

### Falco可检测到的内容

falco可检测到文件、进程、网络相关的操作

### Falco功能的体验

首先检查`service falco status`将其关闭,然后直接运行falco即可

```
falco
```

此时运行

```bash
docker run --privileged -i -t ubuntu:18.04 /bin/bash
```

查看falco日志如下

```bash
root@snappyjackPC:~# falco
Wed Mar 10 17:01:11 2021: Falco version 0.27.0 (driver version 5c0b863ddade7a45568c0ac97d037422c9efb750)
Wed Mar 10 17:01:11 2021: Falco initialized with configuration file /etc/falco/falco.yaml
Wed Mar 10 17:01:11 2021: Loading rules from file /etc/falco/falco_rules.yaml:
Wed Mar 10 17:01:11 2021: Loading rules from file /etc/falco/falco_rules.local.yaml:
Wed Mar 10 17:01:11 2021: Loading rules from file /etc/falco/k8s_audit_rules.yaml:
Wed Mar 10 17:01:12 2021: Starting internal webserver, listening on port 8765
17:01:12.164976000: Notice Privileged container started (user=root user_loginuid=0 command=container:a2df28c40618 naughty_cori (id=a2df28c40618) image=ubuntu:18.04)
17:01:59.696573042: Notice Privileged container started (user=root user_loginuid=-1 command=bash naughty_cori (id=a2df28c40618) image=ubuntu:18.04)
```

观察到falco记录到了特殊权限的container已经启动

在etc目录下创建文件

```
root@snappyjackPC:/etc# cat testmorty
```

此时可看到新的告警

```bash
17:07:49.700111506: Error File below /etc opened for writing (user=root user_loginuid=-1 command=cupsd -l parent=systemd pcmdline=systemd splash file=/etc/cups/subscriptions.conf.N program=cupsd gparent=<NA> ggparent=<NA> gggparent=<NA> container_id=host image=<NA>)
17:16:27.410225982: Error File below /etc opened for writing (user=root user_loginuid=0 command=vim testmorty parent=bash pcmdline=bash file=/etc/.testmorty.swp program=vim gparent=sshd ggparent=sshd gggparent=systemd container_id=host image=<NA>)
17:16:27.410258130: Error File below /etc opened for writing (user=root user_loginuid=0 command=vim testmorty parent=bash pcmdline=bash file=/etc/.testmorty.swpx program=vim gparent=sshd ggparent=sshd gggparent=systemd container_id=host image=<NA>)
17:16:27.410305288: Error File below /etc opened for writing (user=root user_loginuid=0 command=vim testmorty parent=bash pcmdline=bash file=/etc/.testmorty.swp program=vim gparent=sshd ggparent=sshd gggparent=systemd container_id=host image=<NA>)
17:16:32.021374810: Error File below /etc opened for writing (user=root user_loginuid=0 command=vim testmorty parent=bash pcmdline=bash file=/etc/testmorty program=vim gparent=sshd ggparent=sshd gggparent=systemd container_id=host image=<NA>
```

配置**/etc/falco/falco_rules.yaml**追加如下内容

```bash
- list: my_programs
  items: [ls, cat, pwd]

- rule: my_programs_opened_file
  desc: track whenever a set of programs opens a file
  condition: proc.name in (my_programs) and evt.type=openat
  output: 一个进程访问了一个文件(user=%user.name command=%proc.cmdline file=%fd.name)
  priority: INFO
```

**/etc/falco/falco_rules.local.yaml**追加如下内容

```
- list: my_programs
  append: true
  items: [cp]
```

这样会触发

```bash
10:52:47.523716713: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=<NA>)
10:52:47.523724688: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=/etc/ld.so.preload)
10:52:47.523743772: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=<NA>)
10:52:47.523747798: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=/etc/ld.so.cache)
10:52:47.523771279: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=<NA>)
10:52:47.523776635: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=/lib/x86_64-linux-gnu/libselinux.so.1)
10:52:47.523888698: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=<NA>)
10:52:47.523896086: Notice 一个进程访问了一个文件(user=root command=ls --color=auto file=/lib/x86_64-linux-gnu/libc.so.6)
```

继续添加**/etc/falco/falco_rules.yaml**

```
- macro: access_file
  condition: evt.type=open

- rule: program_accesses_file
  desc: track whenever a set of programs opens a file
  condition: proc.name in (cat, ls) and (access_file)
  output: a tracked program opened a file (user=%user.name command=%proc.cmdline file=%fd.name)
  priority: INFO
```

**/etc/falco/falco_rules.local.yaml**

```
- macro: access_file
  append: true
  condition: or evt.type=openat
```

此时使用cat或者ls访问的文件都会被记录

```bash
10:53:46.206338963: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=<NA>)
10:53:46.206351161: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=/proc/filesystems)
10:53:46.206473142: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=<NA>)
10:53:46.206479862: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=/usr/lib/locale/locale-archive)
10:53:46.206624761: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=<NA>)
10:53:46.206630132: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=/root)
10:53:46.206796597: Notice 追踪到了一个进程访问了一个文件 (user=root command=ls --color=auto file=<NA>)
```

另一个例子

**/etc/falco/falco_rules.yaml**

```
- rule: program_accesses_file
  desc: track whenever a set of programs opens a file
  condition: proc.name in (cat, ls) and evt.type=open
  output: a tracked program opened a file (user=%user.name command=%proc.cmdline file=%fd.name)
  priority: INFO
```

**/etc/falco/falco_rules.local.yaml**

```yaml
- rule: program_accesses_file
  append: true
  condition: and not user.name=root
```

此时只有非root使用cat或者ls访问的文件才会被记录

网络连接测试如下

添加c2_list至falco_rules.yaml如下

```yaml
- list: c2_server_ip_list
  items: ['"47.240.167.128"', '"114.114.114.114"']
```

展示的日志如下

```
15:27:52.128711972: Warning Outbound connection to C2 server (command=curl http://snappyzz.com:65432 connection=192.168.1.197:46686->47.240.167.128:65432 user=root user_loginuid=0 container_id=host image=<NA>)
```

发送udp

```
sr1(IP(dst="47.240.167.128")/UDP(dport=65432))
```

发送tcp

```
sr1(IP(dst="47.240.167.128")/TCP(dport=65432))
```

udp

```yaml
- rule: 所有udp请求
  desc: upd请求测试
  condition: fd.l4proto=udp
  output: >
    发送了一个upd请求
    (user=%user.name user_loginuid=%user.loginuid command=%proc.cmdline connection=%fd.name proto=%fd.l4proto evt=%evt.type %evt.args container_id=%container.id image=%container.image.repository)
  priority: NOTICE
```

运行nslookup baidu.com 结果如下

```yaml
12:59:50.946208948: Notice 发送了一个upd请求 (user=root user_loginuid=0 command=nslookup baidu.com connection=127.0.0.1:46802->127.0.0.1:46802 proto=udp evt=sendmsg res=1 data=.  container_id=host image=<NA>)
12:59:50.946210156: Notice 发送了一个upd请求 (user=root user_loginuid=0 command=nslookup baidu.com connection=127.0.0.1:46802->127.0.0.1:46802 proto=udp evt=recvmsg fd=6(<4u>127.0.0.1:46802->127.0.0.1:46802)  container_id=host image=<NA>)
12:59:50.946211479: Notice 发送了一个upd请求 (user=root user_loginuid=0 command=nslookup baidu.com connection=127.0.0.1:46802->127.0.0.1:46802 proto=udp evt=recvmsg res=1 size=1 data=. tuple=127.0.0.1:46802->127.0.0.1:46802  container_id=host image=<NA>)
12:59:50.946228616: Notice 发送了一个upd请求 (user=root user_loginuid=0 command=nslookup baidu.com connection=::1:52308->::1:52308 proto=udp evt=sendmsg res=1 data=.  container_id=host image=<NA>)
12:59:50.946229366: Notice 发送了一个upd请求 (user=root user_loginuid=0 command=nslookup baidu.com connection=::1:52308->::1:52308 proto=udp evt=recvmsg fd=6(<6u>::1:52308->::1:52308)  container_id=host image=<NA>)
12:59:50.946230293: Notice 发送了一个upd请求 (user=root user_loginuid=0 command=nslookup baidu.com connection=::1:52308->::1:52308 proto=udp evt=recvmsg res=1 size=1 data=. tuple=::1:52308->::1:52308  container_id=host image=<NA>)
```

tcp

```yaml
- rule: 所有tcp请求
  desc: tcp请求测试
  condition: fd.l4proto=tcp
  output: >
    发送了一个tcp请求
    (user=%user.name user_loginuid=%user.loginuid command=%proc.cmdline connection=%fd.name proto=%fd.l4proto evt=%evt.type %evt.args container_id=%container.id image=%container.image.repository)
  priority: NOTICE
```

结果如下

```yaml
14:48:58.447115506: Notice 发送了一个tcp请求 (user=root user_loginuid=0 command=curl http://snappyzz.com connection=192.168.1.197:34766->47.240.167.128:80 proto=tcp evt=connect res=-115(EINPROGRESS) tuple=192.168.1.197:34766->47.240.167.128:80  container_id=host image=<NA>)
14:48:58.489520564: Notice 发送了一个tcp请求 (user=root user_loginuid=0 command=curl http://snappyzz.com connection=192.168.1.197:34766->47.240.167.128:80 proto=tcp evt=sendto fd=5(<4t>192.168.1.197:34766->47.240.167.128:80) size=76 tuple=NULL  container_id=host image=<NA>)
14:48:58.489533799: Notice 发送了一个tcp请求 (user=root user_loginuid=0 command=curl http://snappyzz.com connection=192.168.1.197:34766->47.240.167.128:80 proto=tcp evt=sendto res=76 data=GET / HTTP/1.1..Host: snappyzz.com..User-Agent: curl/7.68.0..Accept: */*....  container_id=host image=<NA>)
14:48:58.530255574: Notice 发送了一个tcp请求 (user=root user_loginuid=0 command=curl http://snappyzz.com connection=192.168.1.197:34766->47.240.167.128:80 proto=tcp evt=recvfrom fd=5(<4t>192.168.1.197:34766->47.240.167.128:80) size=102400  container_id=host image=<NA>)
14:48:58.530263473: Notice 发送了一个tcp请求 (user=root user_loginuid=0 command=curl http://snappyzz.com connection=192.168.1.197:34766->47.240.167.128:80 proto=tcp evt=recvfrom res=289 data=HTTP/1.1 200 OK..Server: nginx/1.14.1..Date: Fri, 12 Mar 2021 06:48:52 GMT..Cont tuple=NULL  container_id=host image=<NA>)
```

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/about_falco.png)

https://www.sans.org/reading-room/whitepapers/detection/container-intrusions-assessing-efficacy-intrusion-detection-analysis-methods-linux-container-environments-38245



## 对比sysdig

```bash
root@snappyjackPC:~# sysdig fd.l4proto=tcp and proc.name=curl
10865 15:01:03.737219028 4 curl (81593) < connect res=-115(EINPROGRESS) tuple=192.168.1.197:34772->47.240.167.128:80
11778 15:01:04.779832054 4 curl (81593) < getsockopt res=0 fd=5(<4t>192.168.1.197:34772->47.240.167.128:80) level=1(SOL_SOCKET) optname=4(SO_ERROR) val=0 optlen=4
11783 15:01:04.779871418 4 curl (81593) > sendto fd=5(<4t>192.168.1.197:34772->47.240.167.128:80) size=76 tuple=NULL
11784 15:01:04.779910060 4 curl (81593) < sendto res=76 data=GET / HTTP/1.1..Host: snappyzz.com..User-Agent: curl/7.68.0..Accept: */*....
11879 15:01:04.820063356 4 curl (81593) > recvfrom fd=5(<4t>192.168.1.197:34772->47.240.167.128:80) size=102400
11880 15:01:04.820070756 4 curl (81593) < recvfrom res=289 data=HTTP/1.1 200 OK..Server: nginx/1.14.1..Date: Fri, 12 Mar 2021 07:00:59 GMT..Cont tuple=NULL
11929 15:01:04.820253498 4 curl (81593) > close fd=5(<4t>192.168.1.197:34772->47.240.167.128:80)
11931 15:01:04.820254476 4 curl (81593) < close res=0
```

查看cat访问了哪些文件

```bash
root@snappyjackPC:~# sysdig proc.name=cat and evt.type=openat
2423 11:22:24.023748383 1 cat (24020) > openat
2424 11:22:24.023758900 1 cat (24020) < openat fd=3(<f>/etc/ld.so.preload) dirfd=-100(AT_FDCWD) name=/etc/ld.so.preload flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=10302
2429 11:22:24.023775179 1 cat (24020) > openat
2430 11:22:24.023780686 1 cat (24020) < openat fd=3(<f>/etc/ld.so.cache) dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=10302
2437 11:22:24.023813955 1 cat (24020) > openat
2438 11:22:24.023822852 1 cat (24020) < openat fd=3(<f>/lib/x86_64-linux-gnu/libc.so.6) dirfd=-100(AT_FDCWD) name=/lib/x86_64-linux-gnu/libc.so.6 flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=10302
2487 11:22:24.024409394 1 cat (24020) > openat
2488 11:22:24.024427102 1 cat (24020) < openat fd=3(<f>/usr/lib/locale/locale-archive) dirfd=-100(AT_FDCWD) name=/usr/lib/locale/locale-archive flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=10302
2497 11:22:24.024522281 1 cat (24020) > openat
2498 11:22:24.024528656 1 cat (24020) < openat fd=3(<f>/root/exp2.py) dirfd=-100(AT_FDCWD) name=exp2.py(/root/exp2.py) flags=1(O_RDONLY) mode=0 dev=10302
```

查看ip的交互

```bash
root@snappyjackPC:~# sysdig -c spy_ip 120.253.194.74
------ Read 517B
...........c.2.{j\vp....{+VA..%.?...k.Z.-.. .R.s...jp...I@M.8.P.....;.x......>.......,.0.........+./...$.(.k.#.'.g.....9.....3.....=.<.5./.....u.........zero.security.xindong.com........................3t.........h2.http/1.1.........1.....*.(.........................................+........-.....3.&.$... bi&b..k.J..|.....<..%IK%.)..7..^..................................................................................................................................................................................
------ Read 5B
....l
------ Read 5B
...h..q}&...~..x.....Ff.....U.....h... ...;Jg.....z.......J L..:..!..[8.0.. ........................http/1.1
------ Read 5B
.....
------ Read 5B
..........0...0..l...........h.2.\.....D.0...*.H........0Y1.0...U....US1.0...U....DigiCert Inc1301..U...*RapidSSL TLS DV RSA Mixed SHA256 2020 CA-10...200924000000Z..210925120000Z0!
```

自定义输出的内容

```bash
root@snappyjackPC:~# sysdig -p"%evt.arg.name" proc.name=cat and evt.type=openat
/etc/ld.so.preload
/etc/ld.so.cache
/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/locale/locale-archive
/root/exp2.py
```

参考:

https://cizixs.com/2017/04/27/sysdig-for-linux-system-monitor-and-analysis/