---
layout: post
title: 关于LD_PRELOAD对抗总结
excerpt: "关于LD_PRELOAD对抗"
categories: [知识总结]
comments: true
---

一个例子

```c
#prog.c
#include <stdio.h>

int main(void) {
    printf("Calling the fopen() function...\n");
    FILE *fd = fopen("test.txt","r");
    if (!fd) {
        printf("fopen() returned NULL\n");
        return 1;
    }
    printf("fopen() succeeded\n");
    return 0;
}
```

编译

```
gcc prog.c -o prog
```

现在创建一个myfopen.c

```c
#include <stdio.h>

FILE *fopen(const char *path, const char *mode) {
    printf("Always failing fopen\n");
    return NULL;
}
```

编译

```
gcc -Wall -fPIC -shared -o myfopen.so myfopen.c
```

运行

```
$ LD_PRELOAD=./myfopen.so ./prog
Calling the fopen() function...
Always failing fopen
fopen() returned NULL
```

或者

```
export LD_PRELOAD=myfopen.so
```

后者一个绝对地址

```
export LD_PRELOAD=/root/2119/myfopen.so
```

还有一种方法就是将so写入到指定的文件中

```
sudo sh -c 'echo #{path_to_shared_library} > /etc/ld.so.preload'
```

在环境变量或者/etc/ld.so.preload中查找可用这个方法

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

int main()
{
    if(getenv("LD_PRELOAD"))
        printf("LD_PRELOAD detected through getenv()\n");
    else
        printf("Environment is clean\n");
    if(open("/etc/ld.so.preload", O_RDONLY) > 0)
        printf("/etc/ld.so.preload detected through open()\n");
    else
        printf("/etc/ld.so.preload is not present\n");
}
```

```
% sudo touch /etc/ld.so.preload
% gcc -o detect detect.c 
% LD_PRELOAD= ./detect 
LD_PRELOAD detected through getenv()
/etc/ld.so.preload detected through open()
%
```

既然可以在用户层hook函数，那么我们可以hook open和getenv函数

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

// We will store the real function pointer in here
int (*o_open)(const char*, int oflag) = NULL;
char* (*o_getenv)(const char *) = NULL;

char* getenv(const char *name)
{
    if(!o_getenv)
        // Find the real function pointer
        o_getenv = dlsym(RTLD_NEXT, "getenv");
    if(strcmp(name, "LD_PRELOAD") == 0)
        // This environment variable does not exist, I swear
        return NULL;
    // Everything is ok, call the real getenv
    return o_getenv(name);
}

int open(const char *path, int oflag, ...)
{
    char real_path[PATH_MAX];
    if(!o_open)
        // Find the real function pointer
        o_open = dlsym(RTLD_NEXT, "open");
    // Resolve symbolic links and dot notation fu
    realpath(path, real_path);
    if(strcmp(real_path, "/etc/ld.so.preload") == 0)
    {
        // This file does not exist, I swear.
        errno = ENOENT;
        return -1;
    }
    // Everything is ok, call the real open
    return o_open(path, oflag);
}

// Still many other functions to hook, like fopen, open64, stat, readdir, 
// rename, unlink, etc.
```

这样我们在用之前的方式查找，就不灵了

```
% gcc -shared -fpic -ldl -o stealth_preload.so stealth_preload.c
% LD_PRELOAD=./stealth_preload.so ./detect 
Environment is clean
/etc/ld.so.preload is not present
%
```

这样ldd查看任何elf，都会看到so的加载

```
[root@localhost 2119]# ldd ./prog
	linux-vdso.so.1 =>  (0x00007fff1dbee000)
	./myfopen.so (0x00007f1b563b3000)
	libc.so.6 => /lib64/libc.so.6 (0x00007f1b55fe5000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f1b565b5000)
```

```
[root@localhost 1119]# ldd /usr/bin/python
	linux-vdso.so.1 =>  (0x00007ffe56f25000)
	/root/2119/myfopen.so (0x00007f13a21ca000)
	libpython2.7.so.1.0 => /lib64/libpython2.7.so.1.0 (0x00007f13a1dfe000)
	libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f13a1be2000)
	libdl.so.2 => /lib64/libdl.so.2 (0x00007f13a19de000)
	libutil.so.1 => /lib64/libutil.so.1 (0x00007f13a17db000)
	libm.so.6 => /lib64/libm.so.6 (0x00007f13a14d9000)
	libc.so.6 => /lib64/libc.so.6 (0x00007f13a110b000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f13a23cc000)
```

既然so已经加载到虚拟地址中，那么也可以通过伪文件系统查看

```
[root@localhost ~]# more /proc/25426/maps  | grep myfopen
7f7e0cda2000-7f7e0cda3000 r-xp 00000000 fd:01 132036                     /root/2119/myfopen.so
7f7e0cda3000-7f7e0cfa2000 ---p 00001000 fd:01 132036                     /root/2119/myfopen.so
7f7e0cfa2000-7f7e0cfa3000 r--p 00000000 fd:01 132036                     /root/2119/myfopen.so
7f7e0cfa3000-7f7e0cfa4000 rw-p 00001000 fd:01 132036                     /root/2119/myfopen.so
```

```
$ LD_PRELOAD=/tmp/noenviron_preload.so cat /proc/self/maps
00400000-0040c000 r-xp 00000000 fe:01 400301                             /usr/bin/cat
0060b000-0060c000 r--p 0000b000 fe:01 400301                             /usr/bin/cat
0060c000-0060d000 rw-p 0000c000 fe:01 400301                             /usr/bin/cat
00ef7000-00f18000 rw-p 00000000 00:00 0                                  [heap]
7fce2e877000-7fce2e87a000 r-xp 00000000 fe:01 411128                     /usr/lib/libdl-2.20.so
7fce2e87a000-7fce2ea79000 ---p 00003000 fe:01 411128                     /usr/lib/libdl-2.20.so
7fce2ea79000-7fce2ea7a000 r--p 00002000 fe:01 411128                     /usr/lib/libdl-2.20.so
7fce2ea7a000-7fce2ea7b000 rw-p 00003000 fe:01 411128                     /usr/lib/libdl-2.20.so
7fce2ea7b000-7fce2ec14000 r-xp 00000000 fe:01 418477                     /usr/lib/libc-2.20.so
7fce2ec14000-7fce2ee14000 ---p 00199000 fe:01 418477                     /usr/lib/libc-2.20.so
7fce2ee14000-7fce2ee18000 r--p 00199000 fe:01 418477                     /usr/lib/libc-2.20.so
7fce2ee18000-7fce2ee1a000 rw-p 0019d000 fe:01 418477                     /usr/lib/libc-2.20.so
7fce2ee1a000-7fce2ee1e000 rw-p 00000000 00:00 0 
7fce2ee1e000-7fce2ee1f000 r-xp 00000000 00:1e 20903                      /tmp/noenviron_preload.so
7fce2ee1f000-7fce2f01f000 ---p 00001000 00:1e 20903                      /tmp/noenviron_preload.so
7fce2f01f000-7fce2f020000 rw-p 00001000 00:1e 20903                      /tmp/noenviron_preload.so
7fce2f020000-7fce2f042000 r-xp 00000000 fe:01 412638                     /usr/lib/ld-2.20.so
7fce2f076000-7fce2f200000 r--p 00000000 fe:01 453088                     /usr/lib/locale/locale-archive
7fce2f200000-7fce2f203000 rw-p 00000000 00:00 0 
7fce2f21e000-7fce2f241000 rw-p 00000000 00:00 0 
7fce2f241000-7fce2f242000 r--p 00021000 fe:01 412638                     /usr/lib/ld-2.20.so
7fce2f242000-7fce2f243000 rw-p 00022000 fe:01 412638                     /usr/lib/ld-2.20.so
7fce2f243000-7fce2f244000 rw-p 00000000 00:00 0 
7fff3d885000-7fff3d8a6000 rw-p 00000000 00:00 0                          [stack]
7fff3d8f4000-7fff3d8f6000 r--p 00000000 00:00 0                          [vvar]
7fff3d8f6000-7fff3d8f8000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

通过这种方法的检测脚本如下

```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUFFER_SIZE 256

// Avoid to use libc strstr
// Return a pointer after the first location of sub in str
char* afterSubstr(char *str, const char *sub)
{
    int i, found;
    char *ptr;
    found = 0;
    for(ptr = str; *ptr != '\0'; ptr++)
    {
        found = 1;
        for(i = 0; found == 1 && sub[i] != '\0'; i++)
            if(sub[i] != ptr[i])
                found = 0;
        if(found == 1)
            break;
    }
    if(found == 0)
        return NULL;
    return ptr + i;
}

// Try to match the following regexp: libname-[0-9]+\.[0-9]+\.so$
// Not using any libc function makes that code awful, I know
int isLib(char *str, const char *lib)
{
    int i, found;
    static const char *end = ".so\n";
    char *ptr;
    // Trying to find lib in str
    ptr = afterSubstr(str, lib);
    if(ptr == NULL)
        return 0;
    // Should be followed by a '-'
    if(*ptr != '-')
        return 0;
    // Checking the first [0-9]+\.
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0 || *ptr != '.')
        return 0;
    // Checking the second [0-9]+
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0)
        return 0;
    // Checking if it ends with ".so\n"
    for(i = 0; end[i] != '\0'; i++)
        if(end[i] != ptr[i])
            return 0;
    return 1;
}

int main()
{
    FILE *memory_map;
    char buffer[BUFFER_SIZE];
    int after_libc = 0;
    memory_map = fopen("/proc/self/maps", "r");
    if(memory_map == NULL)
    {
        printf("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt\n");
        return 1;
    }
    // Read the memory map line by line
    // Try to look for a library loaded in between the libc and ld
    while(fgets(buffer, BUFFER_SIZE, memory_map) != NULL)
    {
        // Look for a libc entry
        if(isLib(buffer, "libc"))
            after_libc = 1;
        else if(after_libc)
        {
            // Look for a ld entry
            if(isLib(buffer, "ld"))
            {
                // If we got this far then everythin is fine
                printf("Memory maps are clean\n");
                break;
            }
            // If it's not an anonymous memory map
            else if(afterSubstr(buffer, "00000000 00:00 0") == NULL)
            {
                // Something has been preloaded by ld.so
                printf("LD_PRELOAD detected through memory maps\n");
                break;
            }
        }
    }
}
```

```
$ gcc -o memory_detect memory_detect.c 
$ LD_PRELOAD=./noenviron_preload.so ./memory_detect 
LD_PRELOAD detected through memory maps
```

用这个方法进行查看，也存在hook方式继续进行隐藏的情况

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <limits.h>
#include <errno.h>

FILE* (*o_fopen)(const char*, const char*) = NULL;
char *soname = "fakememory_preload.so";

void fakeMaps(char *original_path, char *fake_path, char *pattern)
{
    FILE *original, *fake;
    char buffer[PATH_MAX];
    original = o_fopen(original_path, "r");
    fake = o_fopen(fake_path, "w");
    // Copy original in fake but discard the lines containing pattern
    while(fgets(buffer, PATH_MAX, original))
        if(strstr(buffer, pattern) == NULL)
            fputs(buffer, fake);
    fclose(fake);
    fclose(original);
}

FILE* fopen(const char *path, const char *mode)
{
    char real_path[PATH_MAX], maps_path[PATH_MAX];
    pid_t pid = getpid();
    if(!o_fopen)
        // Find the real function pointer
        o_fopen = dlsym(RTLD_NEXT, "fopen");
    // Resolve symbolic links and dot notation fu
    realpath(path, real_path);
    snprintf(maps_path, PATH_MAX, "/proc/%d/maps", pid);
    if(strcmp(real_path, maps_path) == 0)
    {
        snprintf(maps_path, PATH_MAX, "/tmp/%d.fakemaps", pid);
        // Create a file in tmp containing our fake map
        fakeMaps(real_path, maps_path, soname);
        return o_fopen(maps_path, mode);
    }
    // Everything is ok, call the real open
    return o_fopen(path, mode);
}
```

```
$ gcc -o fakememory_preload.so -shared -fpic -ldl fakememory_preload.c
$ LD_PRELOAD=./fakememory_preload.so ./memory_detect 
Memory maps are clean
```

既然LD_PRELOAD是在用户层进行hook，我们可以直接调用syscall来进行

```c
 
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUFFER_SIZE 256

int syscall_open(char *path, long oflag)
{
    int fd = -1;
    #ifdef __i386__
    __asm__ (
             "mov $5, %%eax;" // Open syscall number
             "mov %1, %%ebx;" // Address of our string
             "mov %2, %%ecx;" // Open mode
             "mov $0, %%edx;" // No create mode
             "int $0x80;"     // Straight to ring0
             "mov %%eax, %0;" // Returned file descriptor
             :"=r" (fd)
             :"m" (path), "m" (oflag)
             :"eax", "ebx", "ecx", "edx"
             );
    #elif __amd64__
    __asm__ (
             "mov $2, %%rax;" // Open syscall number
             "mov %1, %%rdi;" // Address of our string
             "mov %2, %%rsi;" // Open mode
             "mov $0, %%rdx;" // No create mode
             "syscall;"       // Straight to ring0
             "mov %%eax, %0;" // Returned file descriptor
             :"=r" (fd)
             :"m" (path), "m" (oflag)
             :"rax", "rdi", "rsi", "rdx"
             );
    #endif
    return fd;
 }

size_t syscall_gets(char *buffer, size_t buffer_size, int fd)
{
    size_t i;
    for(i = 0; i < buffer_size-1; i++)
    {
        size_t nbytes;
        #ifdef __i386__
        __asm__ (
                 "mov $3, %%eax;" // Read syscall number
                 "mov %1, %%ebx;" // File descriptor
                 "mov %2, %%ecx;" // Address of our buffer
                 "mov $1, %%edx;" // Read 1 byte
                 "int $0x80;"     // Straight to ring0
                 "mov %%eax, %0;" // Returned read byte number 
                 :"=r" (nbytes)
                 :"m" (fd), "r" (&(buffer[i]))
                 :"eax", "ebx", "ecx", "edx"
                 );
        #elif __amd64__
        __asm__ (
                 "mov $0, %%rax;" // Read syscall number
                 "mov %1, %%rdi;" // File descriptor
                 "mov %2, %%rsi;" // Address of our buffer
                 "mov $1, %%rdx;" // Read 1 byte
                 "syscall;"       // Straight to ring0
                 "mov %%rax, %0;" // Returned read byte number
                 :"=r" (nbytes)
                 :"m" (fd), "r" (&(buffer[i]))
                 :"rax", "rdi", "rsi", "rdx"
                 );
        #endif
        if(nbytes != 1)
            break;
        if(buffer[i] == '\n')
        {
            i++;
            break;
        }
    }
    buffer[i] = '\0';
    return i;
}

// Avoid to use libc strstr
char* afterSubstr(char *str, const char *sub)
{
    int i, found;
    char *ptr;
    found = 0;
    for(ptr = str; *ptr != '\0'; ptr++)
    {
        found = 1;
        for(i = 0; found == 1 && sub[i] != '\0'; i++)
            if(sub[i] != ptr[i])
                found = 0;
        if(found == 1)
            break;
    }
    if(found == 0)
        return NULL;
    return ptr + i;
}

// Try to match the following regexp: libname-[0-9]+\.[0-9]+\.so$
// Not using any libc function makes that code awful, I know
int isLib(char *str, const char *lib)
{
    int i, found;
    static const char *end = ".so\n";
    char *ptr;
    // Trying to find lib in str
    ptr = afterSubstr(str, lib);
    if(ptr == NULL)
        return 0;
    // Should be followed by a '-'
    if(*ptr != '-')
        return 0;
    // Checking the first [0-9]+\.
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0 || *ptr != '.')
        return 0;
    // Checking the second [0-9]+
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0)
        return 0;
    // Checking if it ends with ".so\n"
    for(i = 0; end[i] != '\0'; i++)
        if(end[i] != ptr[i])
            return 0;
    return 1;
}

int main()
{
    int memory_map;
    char buffer[BUFFER_SIZE];
    int after_libc = 0;

    // If the file was succesfully opened
    if(syscall_open("/etc/ld.so.preload", O_RDONLY) > 0)
        printf("/etc/ld.so.preload detected through open syscall\n");
    else
        printf("/etc/ld.so.preload is not present\n");
    // Open the memory map through a syscall this time
    memory_map = syscall_open("/proc/self/maps", O_RDONLY);
    if(memory_map == -1)
    {
        printf("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt\n");
        return 1;
    }
    // Read the memory map line by line
    // Try to look for a library loaded in between the libc and ld
    while(syscall_gets(buffer, BUFFER_SIZE, memory_map) != 0)
    {
        // Look for a libc entry
        if(isLib(buffer, "libc"))
            after_libc = 1;
        else if(after_libc)
        {
            // Look for a ld entry
            if(isLib(buffer, "ld"))
            {
                // If we got this far then everythin is fine
                printf("Memory maps are clean\n");
                break;
            }
            // If it's not an anonymous memory map
            else if(afterSubstr(buffer, "00000000 00:00 0") == NULL)
            {
                // Something has been preloaded by ld.so
                printf("LD_PRELOAD detected through memory maps\n");
                break;
            }
        }
    }
}
```

```
$ gcc -o syscall_detect syscall_detect.c 
$ LD_PRELOAD=./fakememory_preload.so ./syscall_detect 
/etc/ld.so.preload detected through open syscall
LD_PRELOAD detected through memory maps
```



注意：export设置的环境变量在重新开启shell会失效,如需持久化，最好的方法是在`.bashrc`中添加

取消ld_preload

```
unset LD_PRELOAD
```

普通的检查方式，通过环境变量和文件位置进行检测

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

int main()
{
    if(getenv("LD_PRELOAD"))
        printf("LD_PRELOAD detected through getenv()\n");
    else
        printf("Environment is clean\n");
    if(open("/etc/ld.so.preload", O_RDONLY) > 0)
        printf("/etc/ld.so.preload detected through open()\n");
    else
        printf("/etc/ld.so.preload is not present\n");
}
```

结果

```bash
% sudo touch /etc/ld.so.preload
% gcc -o detect detect.c 
% LD_PRELOAD= ./detect 
LD_PRELOAD detected through getenv()
/etc/ld.so.preload detected through open()
```

然后就是简单的hook open函数和getenv函数

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

// We will store the real function pointer in here
int (*o_open)(const char*, int oflag) = NULL;
char* (*o_getenv)(const char *) = NULL;

char* getenv(const char *name)
{
    if(!o_getenv)
        // Find the real function pointer
        o_getenv = dlsym(RTLD_NEXT, "getenv");
    if(strcmp(name, "LD_PRELOAD") == 0)
        // This environment variable does not exist, I swear
        return NULL;
    // Everything is ok, call the real getenv
    return o_getenv(name);
}

int open(const char *path, int oflag, ...)
{
    char real_path[PATH_MAX];
    if(!o_open)
        // Find the real function pointer
        o_open = dlsym(RTLD_NEXT, "open");
    // Resolve symbolic links and dot notation fu
    realpath(path, real_path);
    if(strcmp(real_path, "/etc/ld.so.preload") == 0)
    {
        // This file does not exist, I swear.
        errno = ENOENT;
        return -1;
    }
    // Everything is ok, call the real open
    return o_open(path, oflag);
}

// Still many other functions to hook, like fopen, open64, stat, readdir, 
// rename, unlink, etc.
```

此时已无法查找到

```bash
% gcc -shared -fpic -ldl -o stealth_preload.so stealth_preload.c
% LD_PRELOAD=./stealth_preload.so ./detect 
Environment is clean
/etc/ld.so.preload is not present
```

既然preload可以hook任何函数，那么我们就找一个不使用任何函数调用的方法来检查环境变量：通过读取内存来检查，其中Linux C中environ 变量是一个char** 类型，存储着系统的环境变量

```c
#include <stdio.h>

// This will resolve at linking time
extern char **environ;

int main()
{
    long i, j;
    char env[] = "LD_PRELOAD";
    // Go through all environment strings, the end of the array 
    // is marked by a null pointer.
    for(i = 0; environ[i]; i++)
    {
        // Check is the string begins by LD_PRELOAD
        // I said NO CALL not even to strstr
        for(j = 0; env[j] != '\0' && environ[i][j] != '\0'; j++)
            if(env[j] != environ[i][j])
                break;
        // If the complete chain was found
        if(env[j] == '\0')
        {
            printf("LD_PRELOAD detected through environ\n");
            return;
        }
    }
    printf("Environment is clean\n");
}
```

运行结果

```bash
% gcc -o nocall_detect nocall_detect.c 
% LD_PRELOAD=./stealth_preload.so ./nocall_detect
LD_PRELOAD detected through environ
```

这个也有一个绕过方法，就是在hook函数之后，再把内存中的字段删除掉，我们可以在init()中进行相关操作,而如果这个进程产生了子进程，那么他将不再继承LD_PRELOAD环境变量（因为已经删掉了），所以我们要在execve之前再加上这个环境变量

下面这个方法就是hook了init函数和execve函数,添加删除内存特定内容的功能

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern char **environ;

int (*o_execve)(const char *path, char *const argv[], char *const envp[]) = NULL;

char *sopath;

// Called as soon as the library is loaded, the program has not executed any 
// instructions yet.
void init()
{
    int i, j;
    static const char *ldpreload = "LD_PRELOAD";
    // First save the value of LD_PRELOAD
    int len = strlen(getenv(ldpreload));
    sopath = (char*) malloc(len+1);
    strcpy(sopath, getenv(ldpreload));
    // unsetenv() has a weird behavior, this is a custom implementation
    // Look for LD_PRELOAD variable
    for(i = 0; environ[i]; i++)
    {
        int found = 1;
        for(j = 0; ldpreload[j] != '\0' && environ[i][j] != '\0'; j++)
            if(ldpreload[j] != environ[i][j])
            {
                found = 0;
                break;
            }
        if(found)
        {
            // Set to zero the variable
            for(j = 0; environ[i][j] != '\0'; j++)
                environ[i][j] = '\0';
            break;
            // Free that memory
            free((void*)environ[i]);
        }
    }
    // Remove the string pointer from environ
    for(j = i; environ[j]; j++)
        environ[j] = environ[j+1];
}


int execve(const char *path, char *const argv[], char *const envp[])
{
    int i, j, ldi = -1, r;
    char** new_env;
    if(!o_execve)
        o_execve = dlsym(RTLD_NEXT,"execve");
    // Look if the provided environment already contains LD_PRELOAD
    for(i = 0; envp[i]; i++)
    {
        if(strstr(envp[i], "LD_PRELOAD"))
            ldi = i;
    }
    // If it doesn't, add it at the end
    if(ldi == -1)
    {
        ldi = i;
        i++;
    }
    // Create a new environment
    new_env = (char**) malloc((i+1)*sizeof(char*));
    // Copy the old environment in the new one, except for LD_PRELOAD
    for(j = 0; j < i; j++)
    {
        // Overwrite or create the LD_PRELOAD variable
        if(j == ldi)
        {
            new_env[j] = (char*) malloc(256);
            strcpy(new_env[j], "LD_PRELOAD=");
            strcat(new_env[j], sopath);
        }
        else
            new_env[j] = (char*) envp[j];
    }
    // That string array is NULL terminated
    new_env[i] = NULL;
    r = o_execve(path, argv, new_env);
    free(new_env[ldi]);
    free(new_env);
    return r;
}
// You also have to patch all the other variants of exec
```

结果显示，通过内存查找的方法已经无法找到

```bash
$ gcc -o noenviron_preload.so -shared -fpic -ldl -Wl,-init,init noenviron_preload.c
$ LD_PRELOAD=./noenviron_preload.so ./nocall_detect 
Environment is clean
```

#### 基于内存的排查

除了查看ld.so.preload文件和环境变量，还有其他的方法也可以检测，比如读取proc中的map文件

```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUFFER_SIZE 256

// Avoid to use libc strstr
// Return a pointer after the first location of sub in str
char* afterSubstr(char *str, const char *sub)
{
    int i, found;
    char *ptr;
    found = 0;
    for(ptr = str; *ptr != '\0'; ptr++)
    {
        found = 1;
        for(i = 0; found == 1 && sub[i] != '\0'; i++)
            if(sub[i] != ptr[i])
                found = 0;
        if(found == 1)
            break;
    }
    if(found == 0)
        return NULL;
    return ptr + i;
}

// Try to match the following regexp: libname-[0-9]+\.[0-9]+\.so$
// Not using any libc function makes that code awful, I know
int isLib(char *str, const char *lib)
{
    int i, found;
    static const char *end = ".so\n";
    char *ptr;
    // Trying to find lib in str
    ptr = afterSubstr(str, lib);
    if(ptr == NULL)
        return 0;
    // Should be followed by a '-'
    if(*ptr != '-')
        return 0;
    // Checking the first [0-9]+\.
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0 || *ptr != '.')
        return 0;
    // Checking the second [0-9]+
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0)
        return 0;
    // Checking if it ends with ".so\n"
    for(i = 0; end[i] != '\0'; i++)
        if(end[i] != ptr[i])
            return 0;
    return 1;
}

int main()
{
    FILE *memory_map;
    char buffer[BUFFER_SIZE];
    int after_libc = 0;
    memory_map = fopen("/proc/self/maps", "r");
    if(memory_map == NULL)
    {
        printf("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt\n");
        return 1;
    }
    // Read the memory map line by line
    // Try to look for a library loaded in between the libc and ld
    while(fgets(buffer, BUFFER_SIZE, memory_map) != NULL)
    {
        // Look for a libc entry
        if(isLib(buffer, "libc"))
            after_libc = 1;
        else if(after_libc)
        {
            // Look for a ld entry
            if(isLib(buffer, "ld"))
            {
                // If we got this far then everythin is fine
                printf("Memory maps are clean\n");
                break;
            }
            // If it's not an anonymous memory map
            else if(afterSubstr(buffer, "00000000 00:00 0") == NULL)
            {
                // Something has been preloaded by ld.so
                printf("LD_PRELOAD detected through memory maps\n");
                break;
            }
        }
    }
}
```

结果可以看出，通过查看maps检测到了ld_preload

```bash
$ gcc -o memory_detect memory_detect.c 
$ LD_PRELOAD=./noenviron_preload.so ./memory_detect 
LD_PRELOAD detected through memory maps
```

同样是由于可以hook任意函数，我们可以hook *open()*, *open64()*, *openat64()*,  *freopen()* 等函数，伪造一个虚假的maps

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <limits.h>
#include <errno.h>

FILE* (*o_fopen)(const char*, const char*) = NULL;
char *soname = "fakememory_preload.so";

void fakeMaps(char *original_path, char *fake_path, char *pattern)
{
    FILE *original, *fake;
    char buffer[PATH_MAX];
    original = o_fopen(original_path, "r");
    fake = o_fopen(fake_path, "w");
    // Copy original in fake but discard the lines containing pattern
    while(fgets(buffer, PATH_MAX, original))
        if(strstr(buffer, pattern) == NULL)
            fputs(buffer, fake);
    fclose(fake);
    fclose(original);
}

FILE* fopen(const char *path, const char *mode)
{
    char real_path[PATH_MAX], maps_path[PATH_MAX];
    pid_t pid = getpid();
    if(!o_fopen)
        // Find the real function pointer
        o_fopen = dlsym(RTLD_NEXT, "fopen");
    // Resolve symbolic links and dot notation fu
    realpath(path, real_path);
    snprintf(maps_path, PATH_MAX, "/proc/%d/maps", pid);
    if(strcmp(real_path, maps_path) == 0)
    {
        snprintf(maps_path, PATH_MAX, "/tmp/%d.fakemaps", pid);
        // Create a file in tmp containing our fake map
        fakeMaps(real_path, maps_path, soname);
        return o_fopen(maps_path, mode);
    }
    // Everything is ok, call the real open
    return o_fopen(path, mode);
}
```

结果如下,我们hook了fopen等函数，制造了虚假的maps

```bash
$ gcc -o fakememory_preload.so -shared -fpic -ldl fakememory_preload.c
$ LD_PRELOAD=./fakememory_preload.so ./memory_detect 
Memory maps are clean
```

现在我们直接调用syscall来绕过，通过直接调用syscall来实现读取ld.so.preload和读取maps

```c
 
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUFFER_SIZE 256

int syscall_open(char *path, long oflag)
{
    int fd = -1;
    #ifdef __i386__
    __asm__ (
             "mov $5, %%eax;" // Open syscall number
             "mov %1, %%ebx;" // Address of our string
             "mov %2, %%ecx;" // Open mode
             "mov $0, %%edx;" // No create mode
             "int $0x80;"     // Straight to ring0
             "mov %%eax, %0;" // Returned file descriptor
             :"=r" (fd)
             :"m" (path), "m" (oflag)
             :"eax", "ebx", "ecx", "edx"
             );
    #elif __amd64__
    __asm__ (
             "mov $2, %%rax;" // Open syscall number
             "mov %1, %%rdi;" // Address of our string
             "mov %2, %%rsi;" // Open mode
             "mov $0, %%rdx;" // No create mode
             "syscall;"       // Straight to ring0
             "mov %%eax, %0;" // Returned file descriptor
             :"=r" (fd)
             :"m" (path), "m" (oflag)
             :"rax", "rdi", "rsi", "rdx"
             );
    #endif
    return fd;
 }

size_t syscall_gets(char *buffer, size_t buffer_size, int fd)
{
    size_t i;
    for(i = 0; i < buffer_size-1; i++)
    {
        size_t nbytes;
        #ifdef __i386__
        __asm__ (
                 "mov $3, %%eax;" // Read syscall number
                 "mov %1, %%ebx;" // File descriptor
                 "mov %2, %%ecx;" // Address of our buffer
                 "mov $1, %%edx;" // Read 1 byte
                 "int $0x80;"     // Straight to ring0
                 "mov %%eax, %0;" // Returned read byte number 
                 :"=r" (nbytes)
                 :"m" (fd), "r" (&(buffer[i]))
                 :"eax", "ebx", "ecx", "edx"
                 );
        #elif __amd64__
        __asm__ (
                 "mov $0, %%rax;" // Read syscall number
                 "mov %1, %%rdi;" // File descriptor
                 "mov %2, %%rsi;" // Address of our buffer
                 "mov $1, %%rdx;" // Read 1 byte
                 "syscall;"       // Straight to ring0
                 "mov %%rax, %0;" // Returned read byte number
                 :"=r" (nbytes)
                 :"m" (fd), "r" (&(buffer[i]))
                 :"rax", "rdi", "rsi", "rdx"
                 );
        #endif
        if(nbytes != 1)
            break;
        if(buffer[i] == '\n')
        {
            i++;
            break;
        }
    }
    buffer[i] = '\0';
    return i;
}

// Avoid to use libc strstr
char* afterSubstr(char *str, const char *sub)
{
    int i, found;
    char *ptr;
    found = 0;
    for(ptr = str; *ptr != '\0'; ptr++)
    {
        found = 1;
        for(i = 0; found == 1 && sub[i] != '\0'; i++)
            if(sub[i] != ptr[i])
                found = 0;
        if(found == 1)
            break;
    }
    if(found == 0)
        return NULL;
    return ptr + i;
}

// Try to match the following regexp: libname-[0-9]+\.[0-9]+\.so$
// Not using any libc function makes that code awful, I know
int isLib(char *str, const char *lib)
{
    int i, found;
    static const char *end = ".so\n";
    char *ptr;
    // Trying to find lib in str
    ptr = afterSubstr(str, lib);
    if(ptr == NULL)
        return 0;
    // Should be followed by a '-'
    if(*ptr != '-')
        return 0;
    // Checking the first [0-9]+\.
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0 || *ptr != '.')
        return 0;
    // Checking the second [0-9]+
    found = 0;
    for(ptr += 1; *ptr >= '0' && *ptr <= '9'; ptr++)
        found = 1;
    if(found == 0)
        return 0;
    // Checking if it ends with ".so\n"
    for(i = 0; end[i] != '\0'; i++)
        if(end[i] != ptr[i])
            return 0;
    return 1;
}

int main()
{
    int memory_map;
    char buffer[BUFFER_SIZE];
    int after_libc = 0;

    // If the file was succesfully opened
    if(syscall_open("/etc/ld.so.preload", O_RDONLY) > 0)
        printf("/etc/ld.so.preload detected through open syscall\n");
    else
        printf("/etc/ld.so.preload is not present\n");
    // Open the memory map through a syscall this time
    memory_map = syscall_open("/proc/self/maps", O_RDONLY);
    if(memory_map == -1)
    {
        printf("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt\n");
        return 1;
    }
    // Read the memory map line by line
    // Try to look for a library loaded in between the libc and ld
    while(syscall_gets(buffer, BUFFER_SIZE, memory_map) != 0)
    {
        // Look for a libc entry
        if(isLib(buffer, "libc"))
            after_libc = 1;
        else if(after_libc)
        {
            // Look for a ld entry
            if(isLib(buffer, "ld"))
            {
                // If we got this far then everythin is fine
                printf("Memory maps are clean\n");
                break;
            }
            // If it's not an anonymous memory map
            else if(afterSubstr(buffer, "00000000 00:00 0") == NULL)
            {
                // Something has been preloaded by ld.so
                printf("LD_PRELOAD detected through memory maps\n");
                break;
            }
        }
    }
}
```

结果如下：我们使用syscall绕过了关于hook的隐藏姿势

```bash
$ gcc -o syscall_detect syscall_detect.c 
$ LD_PRELOAD=./fakememory_preload.so ./syscall_detect 
/etc/ld.so.preload detected through open syscall
LD_PRELOAD detected through memory maps
```

然而这也并不是万能的方法，现在有两种方式可以来改变syscall的行为

- SECCOMP可以限制syscall的调用，这个功能本是用来做sandbox的
- Ptrace用来debug进程，并且允许在每次调用syscall之前或者之后停止进程的运行

我们就用Ptrace这个特性，如果是open syscall，我们就将执行流程交给hook函数,而hook函数的内容就是我们用汇编语言模拟的函数调用，代码如下

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <asm/unistd.h>


// Some useful defines to make the code architecture independent
#if defined(__i386__)
#define REG_SYSCALL ORIG_EAX
#define REG_SP esp
#define REG_IP eip 
#elif defined(__x86_64__)
#define REG_SYSCALL ORIG_RAX
#define REG_SP rsp
#define REG_IP rip 
#endif

long NOHOOK = 0;
char *soname = "nosyscall_preload.so";

void fakeMaps(char *original_path, char *fake_path, char *pattern)
{
    FILE *original, *fake;
    char buffer[PATH_MAX];
    original = fopen(original_path, "r");
    fake = fopen(fake_path, "w");
    // Copy original in fake but discard the lines containing pattern
    while(fgets(buffer, PATH_MAX, original))
        if(strstr(buffer, pattern) == NULL)
            fputs(buffer, fake);
    fclose(fake);
    fclose(original);
}

long open_gate(const char *path, long oflag, long cflag) 
{
    char real_path[PATH_MAX], maps_path[PATH_MAX];
    long ret;
    pid_t pid;
    pid = getpid();
    // Resolve symbolic links and dot notation fu
    realpath(path, real_path);
    snprintf(maps_path, PATH_MAX, "/proc/%d/maps", pid);
    if(strcmp(real_path, "/etc/ld.so.preload") == 0)
    {
        // This file does not exist, I swear.
        errno = ENOENT;
        ret = -1;
    }
    else if(strcmp(real_path, maps_path) == 0)
    {
        snprintf(maps_path, PATH_MAX, "/tmp/%d.fakemaps", pid);
        // Create a file in tmp containing our fake map
        NOHOOK = 1; // Entering NOHOOK section
        fakeMaps(real_path, maps_path, soname);
        ret = open(maps_path, oflag);
    }
    else
    {
        // Everything is ok, call the real open
        NOHOOK = 1; // Entering NOHOOK section
        ret = open(path, oflag, cflag);
    }
    // Exiting NOHOOK section
    NOHOOK = 0;
    #ifdef __i386__
    // Tricky stack cleaning and return in the x86 case
    // We need to clean the 3 arguments (12 bytes) that were pushed on the stack
    __asm__ __volatile__ ("mov %0, %%eax;" // set the return value
                          "mov (%%ebp), %%ecx;" // move saved ebp 12 bytes up
                          "mov %%ecx, 0xc(%%ebp);"
                          "mov 0x4(%%ebp), %%ecx;" // move saved eip 12 bytes up
                          "mov %%ecx, 0x10(%%ebp);"
                          "add $0xc, %%ebp;" //move stack base 12 bytes up
                          "leave;" // normal leave and return
                          "ret;"
                          :
                          :"m" (ret)
                          :
                          );
    #endif
    return ret;
}

void init()
{
    pid_t program;
    // Forking a child process
    program = fork();
    if(program != 0)
    {
        // Parent process which will debug the program in the child process
        int status;
        long syscall_nr;
        struct user_regs_struct regs;
        // We attach to the child
        if(ptrace(PTRACE_ATTACH, program) != 0)
        {
            printf("Failed to attach to the program.\n");
            exit(1);
        }
        waitpid(program, &status, 0);
        // We are only interested in tracing SYSCALLs
        ptrace(PTRACE_SETOPTIONS, program, 0, PTRACE_O_TRACESYSGOOD);
        while(1)
        {
            ptrace(PTRACE_SYSCALL, program, 0, 0);
            waitpid(program, &status, 0);
            if(WIFEXITED(status) || WIFSIGNALED(status))
                break; // Stop tracing if the parent process terminates
            else if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP|0x80)
            {
                // Getting the syscall number
                syscall_nr = ptrace(PTRACE_PEEKUSER, program, sizeof(long)*REG_SYSCALL);
                // Is it an open syscall ?
                if(syscall_nr == __NR_open)
                {
                    // Getting the value of NOHOOK in the child process
                    NOHOOK = ptrace(PTRACE_PEEKDATA, program, (void*)&NOHOOK);
                    // Only hook the syscall if it's not in a NOHOOK section
                    if(!NOHOOK)
                    {
                        // Now we are going to simulate a call
                        // First get the register state
                        ptrace(PTRACE_GETREGS, program, 0, &regs);
                        // Under x86 we need to push the arguments on the stack
                        #ifdef __i386__
                        regs.REG_SP -= sizeof(long);
                        ptrace(PTRACE_POKEDATA, program, (void*)regs.REG_SP, regs.edx);
                        regs.REG_SP -= sizeof(long);
                        ptrace(PTRACE_POKEDATA, program, (void*)regs.REG_SP, regs.ecx);
                        regs.REG_SP -= sizeof(long);
                        ptrace(PTRACE_POKEDATA, program, (void*)regs.REG_SP, regs.ebx);
                        #endif
                        // Push return address on the stack
                        regs.REG_SP -= sizeof(long);
                        ptrace(PTRACE_POKEDATA, program, (void*)regs.REG_SP, regs.REG_IP);
                        // Set RIP to open_gate address
                        regs.REG_IP = (unsigned long) open_gate;
                        // Finnally set the register
                        ptrace(PTRACE_SETREGS, program, 0, &regs);
                    }
                }
                //We always get a second signal after the syscall
                ptrace(PTRACE_SYSCALL, program, 0, 0);
                waitpid(program, &status, 0);
            }
        }
        exit(0);
    }
    else
    {
        // Child process
        // Sleep a bit to give the parent process enough time to attach
        sleep(0);
    }
}
```

结果如下

```bash
gcc -o nosyscall_preload.so -shared -fpic -Wl,-init,init nosyscall_preload.c
LD_PRELOAD=./nosyscall_preload.so ./syscall_detect
/etc/ld.so.preload is not present
Memory maps are clean
```

虽然我们对syscall进行了hook，但是对于静态编译的文件，由于不会加载动态链接库，所以还是无法对静态文件中的syscall进行hook

参考： https://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/
