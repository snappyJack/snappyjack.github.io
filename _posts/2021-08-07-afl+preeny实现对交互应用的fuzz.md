---
layout: post
title: afl+preeny实现对交互应用的fuzz
excerpt: "先知社区投稿"
categories: [先知社区投稿]
comments: true
---



| 测试应用     | wget   |
| ------------ | ------ |
| 版本号       | 1.19.1 |
| fuzz工具     | afl    |
| 调试工具     | gdb    |
| 交互功能实现 | preeny |

#### wget编译安装

首先wget下载源码,并使用afl-clang-fast进行安装

```
wget https://ftp.gnu.org/gnu/wget/wget-1.19.1.tar.gz
tar zxvf wget-1.19.1.tar.gz
cd wget-1.19.1
CXX=afl-clang-fast++ CC=afl-clang-fast ./configure --prefix=/home/mortywget
AFL_USE_ASAN=1 make
make install
```

验证

```
root@c7c87f16a29d:/home/mortywget/bin# ./wget --version
GNU Wget 1.19.1 built on linux-gnu.
```

### preeny

Preeny项目重写了一些交互的函数,我们可以通过`LD_PRELOAD`预加载机制,对程序中的交互进行修改,例如将socket相关函数改写为从用户输入输出(stdin,stdout)进行交互,从而方便我们使用afl进行fuzz

项目下载地址

```
https://github.com/zardus/preeny
```

此处省略安装过程…

#### 验证preeny是否安装成功

预加载`desock.so`文件,并启动一个socket交互程序wget,若输入的字符串成功当作wget请求的返回值 ,则表明preeny安装配置成功

```
root@c7c87f16a29d:~# LD_PRELOAD="/root/preeny/x86_64-linux-gnu/desock.so" wget localhost:6666 -q -O result < <(echo "success");
GET / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: localhost:6666
Connection: Keep-Alive

root@c7c87f16a29d:~# more result 
success
```

我们看到result文件中包含了"success"字符串,说明preeny已经将我们的输入转化成了http response返回结果,说明我们preeny安装配置无误

### 开始fuzz

本次我们测试wget对于状态码为4xx的接收情况
首先创建我们的payload

```
HTTP/1.1 401 Not Authorized
Content-Type: text/plain; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive

test
```

运行fuzz

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200420175922-9bd3e8be-82ed-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200420175922-9bd3e8be-82ed-1.png)

由于此时wget程序接收到response包后并未及时断开,我们的fuzz过程会非常的慢,甚至出现无法fuzz的情况,运行如下命令可看到wget接收到response包后并未及时断开

```
root@c7c87f16a29d:/home/mortywget/bin# nc -lp 6666 < in/a & ./wget localhost:6666 -F -O /dev/null
[1] 7672
--2020-04-20 07:31:52--  http://localhost:6666/
Resolving localhost... 127.0.0.1, ::1
Connecting to localhost|127.0.0.1|:6666... connected.
HTTP request sent, awaiting response... GET / HTTP/1.1
User-Agent: Wget/1.19.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: localhost:6666
Connection: Keep-Alive

401 Not Authorized
```

对于这种情况,我们可以使用如下命令架起nc,让其返回特定的response包

```
nc -lp 6666 < out/hangs/id\:000000\,src\:000000\,op\:flip1\,pos\:4
```

然后通过gdb调试找到程序卡住的位置

```
gdb-peda$ bt
#0  0x00007ffff65d25b3 in __select_nocancel () at ../sysdeps/unix/syscall-template.S:84
#1  0x00000000004c2450 in select_fd (fd=<optimized out>, maxtime=<optimized out>, wait_for=<optimized out>) at connect.c:714
#2  0x00000000004c34b2 in sock_poll (fd=0x4, timeout=<optimized out>, wait_for=0x1) at connect.c:801
#3  poll_internal (fd=<optimized out>, info=0x0, wf=0x1, timeout=<optimized out>) at connect.c:914
#4  fd_read (fd=0x4, buf=0x7fffffffcd00 "gfedcbazzzzffffgggghhhhiiiiddddeeeeffffccccccccbbbbbbb", 'a' <repeats 29 times>, "bbb", 'a' <repeats 58 times>, 'A' <repeats 56 times>..., 
    bufsize=0xff, timeout=<optimized out>) at connect.c:933
#5  0x000000000052723c in skip_short_body (fd=<optimized out>, contlen=<optimized out>, chunked=<optimized out>) at http.c:989
#6  0x0000000000519a95 in gethttp (u=<optimized out>, original_url=<optimized out>, hs=<optimized out>, dt=<optimized out>, proxy=<optimized out>, iri=<optimized out>, 
    count=<optimized out>) at http.c:3524
#7  0x0000000000512aa7 in http_loop (u=<optimized out>, original_url=<optimized out>, newloc=0x7fffffffe310, local_file=<optimized out>, referer=<optimized out>, dt=<optimized out>, 
    proxy=<optimized out>, iri=<optimized out>) at http.c:4193
#8  0x00000000005556aa in retrieve_url (orig_parsed=<optimized out>, origurl=0x60300000e080 "http://localhost:6666", file=<optimized out>, newloc=<optimized out>, refurl=<optimized out>, 
    dt=<optimized out>, recursive=<optimized out>, iri=<optimized out>, register_status=<optimized out>) at retr.c:817
#9  0x000000000053c77b in main (argc=<optimized out>, argv=0x7fffffffe3f0, argv@entry=0x7fffffffe738) at main.c:2081
#10 0x00007ffff64f5830 in __libc_start_main (main=0x538f70 <main>, argc=0x2, argv=0x7fffffffe738, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7fffffffe728) at ../csu/libc-start.c:291
#11 0x00000000004bf659 in _start ()
```

在确定卡住位置之后,修改其源码,使其强制断开连接,退出程序

在`http.c`的如下位置中分别添加`exit(0)`:

```
tms = datetime_str (time (NULL));

      /* Get the new location (with or without the redirection).  */
      if (hstat.newloc)
        *newloc = xstrdup (hstat.newloc);

      switch (err)
        {
        case HERR: case HEOF: case CONSOCKERR:
        case CONERROR: case READERR: case WRITEFAILED:
        case RANGEERR: case FOPEN_EXCL_ERR: case GATEWAYTIMEOUT:
          /* Non-fatal errors continue executing the loop, which will
             bring them to "while" statement at the end, to judge
             whether the number of tries was exceeded.  */
          exit(0); //手动添加
          printwhat (count, opt.ntry);
          continue;
        case FWRITEERR: case FOPENERR:
          /* Another fatal error.  */
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Cannot write to %s (%s).\n"),
                     quote (hstat.local_file), strerror (errno));
        case HOSTERR: case CONIMPOSSIBLE: case PROXERR: case SSLINITFAILED:
        case CONTNOTSUPPORTED: case VERIFCERTERR: case FILEBADFILE:
        case UNKNOWNATTR:
if (statcode == HTTP_STATUS_UNAUTHORIZED)
    {
      /* Authorization is required.  */
      uerr_t auth_err = RETROK;
      bool retry;
      /* Normally we are not interested in the response body.
         But if we are writing a WARC file we are: we like to keep everyting.  */
      if (warc_enabled)
        {
          int _err;
          type = resp_header_strdup (resp, "Content-Type");
          _err = read_response_body (hs, sock, NULL, contlen, 0,
                                    chunked_transfer_encoding,
                                    u->url, warc_timestamp_str,
                                    warc_request_uuid, warc_ip, type,
                                    statcode, head);
          xfree (type);

          if (_err != RETRFINISHED || hs->res < 0)
            {
              CLOSE_INVALIDATE (sock);
              retval = _err;
              goto cleanup;
            }
          else
            CLOSE_FINISH (sock);
        }
      else
        {
          /* Since WARC is disabled, we are not interested in the response body.  */
          if (keep_alive && !head_only
              && skip_short_body (sock, contlen, chunked_transfer_encoding))
            exit(0); //手动添加
          else
            exit(0); //手动添加
        }

      pconn.authorized = false;
while (contlen > 0 || chunked)
    {
      int ret;
      if (chunked)
        {
          if (remaining_chunk_size == 0)
            {
              char *line = fd_read_line (fd);
              char *endl;
              if (line == NULL)
                break;

              remaining_chunk_size = strtol (line, &endl, 16);
              xfree (line);

              if (remaining_chunk_size == 0)
                {
                  line = fd_read_line (fd);
                  xfree (line);
                  break;
                }
            }

          contlen = MIN (remaining_chunk_size, SKIP_SIZE);
        }

      DEBUGP (("Skipping %s bytes of body: [", number_to_static_string (contlen)));

      ret = fd_read (fd, dlbuf, MIN (contlen, SKIP_SIZE), -1);
      exit(0);//手动添加
      if (ret <= 0)
```

重新编译后再次测试payload,程序已经可以即时退出

```
root@c7c87f16a29d:/home/mortywget/bin# nc -lp 6666 < a & ./wget777 localhost:6666 -F -O /dev/null
[1] 22021
--2020-04-20 09:06:53--  http://localhost:6666/
Resolving localhost... 127.0.0.1, ::1
Connecting to localhost|127.0.0.1|:6666... connected.
HTTP request sent, awaiting response... 401 Not Authorized
```

此时再次fuzz,发现hang数量明显减少,速度有所增加

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200420180325-2ca3c8a0-82ee-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200420180325-2ca3c8a0-82ee-1.png)

运行后不久便fuzz出了一个crash

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20200420175149-8dd2b4da-82ec-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200420175149-8dd2b4da-82ec-1.png)

查看crash内容

```
root@c7c87f16a29d:/home/mortywget/bin# xxd out_777/3/crashes/id\:000000\,sig\:06\,src\:000024+000208\,op\:splice\,rep\:16 
00000000: 4854 5450 2f31 2e31 2034 3031 204e 6f74  HTTP/1.1 401 Not
00000010: 2041 7574 7a65 646e 5563 696f 6e3a 5446   AutzednUcion:TF
00000020: 2d38 0a54 7261 6e73 6665 722d 456e 636f  -8.Transfer-Enco
00000030: 6469 6e67 3a20 6368 756e 6b65 640a 436f  ding: chunked.Co
00000040: 6e6e 6563 7469 6f6e 3a20 6b65 0a0a 2d30  nnection: ke..-0
00000050: 7846 4646 4646 4430 3050 2f31 2e31 2034  xFFFFFD00P/1.1 4
00000060: 3031 204e 312e 3120 3430 3120 4e6f 7420  01 N1.1 401 Not 
00000070: 4175 747a 6564 6e55 6369 6f6e 3a54 462d  AutzednUcion:TF-
00000080: 380a 5472 616e 7366 6572 2d45 6e63 6f64  8.Transfer-Encod
00000090: 696e 673a 2063 6875 6e6b 5764 0a43 6f6e  ing: chunkWd.Con
000000a0: 6e65 6374 696f 6e3a 206b 650a 0a2d 3078  nection: ke..-0x
000000b0: 4646 4646 4644 3030 502f 312e 3120 3430  FFFFFD00P/1.1 40
000000c0: 3120 4e6f 7420 416f 6f6f 6f6f 6f6f 6f6f  1 Not Aooooooooo
000000d0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
000000e0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
000000f0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000100: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000110: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000120: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000130: 6f6f 6f6f 6f6f 6f6f 6f6f 7574 7a65 646e  ooooooooooutzedn
00000140: 5563 696f 6e3a 5446 2d38 0a54 7261 6e73  Ucion:TF-8.Trans
00000150: 6665 722d 456e 636f 6469 6e67 3a20 6368  fer-Encoding: ch
00000160: 756e 6565 640a 436f 6e6e 6563 7469 6f6e  uneed.Connection
00000170: 3a20 6b65 0a0a 4030 7846 4646 2034 3031  : ke..@0xFFF 401
00000180: 204e 312e 3120 3430 3120 4e6f 7420 4175   N1.1 401 Not Au
00000190: 0000 0064 6e55 6369 6f6e 3a54 462d 380a  ...dnUcion:TF-8.
000001a0: 5472 616e 7366 6572 2d45 6e63 6f64 696e  Transfer-Encodin
000001b0: 673a 2063 6875 6e6b 5764 0a43 6f6e 6e65  g: chunkWd.Conne
000001c0: 6374 696f 6e3a 206b 650a 0a2d 3078 4646  ction: ke..-0xFF
000001d0: 4646 4644 3030 502f 312e 3120 3430 3120  FFFD00P/1.1 401 
000001e0: 4e6f 7420 416f 6f6f 6f6f 6f6f 6f6f 6f6f  Not Aooooooooooo
000001f0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000200: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000210: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000220: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000230: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000240: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000250: 6f6f 6f6f 6f6f 6f6f 7574 7a65 646e 5563  ooooooooutzednUc
00000260: 696f 6e3a 5446 2d38 0a54 7261 6e73 6665  ion:TF-8.Transfe
00000270: 722d 456e 636f 6469 6e67 3a20 6368 756e  r-Encoding: chun
00000280: 6565 640a 436f 6e6e 6563 7469 6f6e 3a20  eed.Connection: 
00000290: 6b65 0a0a 4030 7846 4646 4646 4430 666f  ke..@0xFFFFFD0fo
000002a0: 7420 4175 747a 7464 6e55 6369 1f1f 1f1f  t AutztdnUci....
000002b0: 1f1f 1f1f 1f1f 1f1f 1f1f 1f1f 1f1f 1f1f  ................
000002c0: 1f1f 1f1f 1f1f 1f1f 1f1f 1f1f 1f1f 1f1f  ................
000002d0: 1f1f 6e65 6374 696f 6e3a 206b 650a 0a2d  ..nection: ke..-
000002e0: 3046 4644 3066 6f74 2041 7574 7a74 646e  0FFD0fot Autztdn
000002f0: 5563 696f 6e3a 5446 2d38 0a54 7255 6e73  Ucion:TF-8.TrUns
00000300: 6665 012d 456e 636f 6469 6e67 3a20 6368  fe.-Encoding: ch
00000310: 756e 6b65 640a 436f 6e6e 6563 7469 6f6e  unked.Connection
00000320: 3a20 6b65 0a0a 2d30 784b 4646 4646 4430  : ke..-0xKFFFFD0
00000330: 300e 62                                  0.b
```

使用gdb进行漏洞验证

```
gdb-peda$ r localhost:6666
Starting program: /home/mortywget/bin/wget localhost:6666
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
--2020-04-20 09:17:49--  http://localhost:6666/
Resolving localhost... 127.0.0.1, ::1
Connecting to localhost|127.0.0.1|:6666... connected.
HTTP request sent, awaiting response... 401 Not AutzednUcion:TF-8
=================================================================
==30736==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffffffcf01 at pc 0x000000445f10 bp 0x7fffffffcc50 sp 0x7fffffffc410
WRITE of size 689 at 0x7fffffffcf01 thread T0
[New process 31313]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
process 31313 is executing new program: /usr/local/bin/llvm-symbolizer
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    #0 0x445f0f in read /root/llvmmorty/llvm-3.5.0.src/projects/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc:345:16
    #1 0x4c361a in sock_read /home/wget-1.19.1/src/connect.c:783:11
    #2 0x4c361a in fd_read /home/wget-1.19.1/src/connect.c:938
    #3 0x52723b in skip_short_body /home/wget-1.19.1/src/http.c:989:13
    #4 0x519a94 in gethttp /home/wget-1.19.1/src/http.c:3524:18
    #5 0x512aa6 in http_loop /home/wget-1.19.1/src/http.c:4193:13
    #6 0x5556a9 in retrieve_url /home/wget-1.19.1/src/retr.c:817:16
    #7 0x53c77a in main /home/wget-1.19.1/src/main.c:2081:15
    #8 0x7ffff64f582f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #9 0x4bf658 in _start (/home/mortywget/bin/wget+0x4bf658)

Address 0x7fffffffcf01 is located in stack of thread T0 at offset 545 in frame
    #0 0x526f4f in skip_short_body /home/wget-1.19.1/src/http.c:947

  This frame has 2 object(s):
    [32, 545) 'dlbuf'
    [688, 696) 'endl' <== Memory access at offset 545 partially underflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism or swapcontext
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /root/llvmmorty/llvm-3.5.0.src/projects/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc:345 read
Shadow bytes around the buggy address:
  0x10007fff7990: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
  0x10007fff79a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff79b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff79c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff79d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10007fff79e0:[01]f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2
  0x10007fff79f0: f2 f2 00 f3 f3 f3 f3 f3 00 00 00 00 00 00 00 00
  0x10007fff7a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7a10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7a20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7a30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  ASan internal:           fe
==30736==ABORTING
[Inferior 2 (process 31313) exited normally]
```

程序在`http.c:skip_short_body()`发生了溢出,在网上对该漏洞进行查找,找到该漏洞正是CVE-2017-13089

https://www.cvedetails.com/cve/CVE-2017-13089/

至此完整的fuzz过程全部结束,对于该漏洞shellcode的编写,请看https://snappyjack.github.io/articles/2019-12/CVE-2017-13089