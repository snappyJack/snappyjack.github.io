---
layout: post
title: CVE-2018-16370 PECSM-TEAM 2.2.2 has a file upload vulnerability
excerpt: "Just about everything you'll need to style in the theme: headings, paragraphs, blockquotes, tables, code blocks, and more."
categories: [hello world]
comments: true
---

This page let user upgrade the PESCMS system manually.

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(1).png)

Follow the mtUpgrade funtction,the upload file extension must be “zip”

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(2).png)

and follow the unzip function

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(3).png)

Follow the simulateInstall function and install function,we can see the file decompression in root directory

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(4).png)

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(5).png)

so,we can create a evil.php

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(6).png)

and compression it as evil.zip,and upload the evil.zip,

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(7).png)

at last ,the system decompress evil.zip and evil.php in root directory.

![Image text](https://raw.githubusercontent.com/snappyJack/snappyjack.github.io/master/img/CVE-2018-16370(8).png)
