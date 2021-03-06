// client.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <thread>
#include "common.h"


//计算校验和
USHORT checksum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

extern int scanner();
extern int sniffer();
extern int captcp();

bool g_bOnRun = true;
//创建用户命令输入线程
void cmdThread(SOCKET sock)
{
    //用户输入请求命令
    while (true) {
        CustomerData data;
        data.clear();
        printf("\nPlease input the message or command you want to send(length less than 512, input exit to exit):\n");
        scanf("%[^\n]", data.data);
        scanf("%*c");
        data.dataLen = strlen(data.data) + 1;
        //处理命令及请求
        if (0 == strcmp(data.data, "exit")) {
            printf("Get exit command, cmdThread terminate!\n");
            g_bOnRun = false;
            break;
        }else if (0 == strcmp(data.data, "scan")) {
            printf("Get scan command, start scanning...\n");
            scanner();
            continue;
        }else if (0 == strcmp(data.data, "sniff")) {
            printf("Get sniff command, start sniffer...\n");
            sniffer();
            continue;
        }
        else if (0 == strcmp(data.data, "captcp")) {
            printf("Get captcp command, start captcp...\n");
            captcp();
            continue;
        }
        ip_header ipHeader;
        tcp_header tcpHeader;
        psd_header psdHeader;
        char Sendto_Buff[MAX_BUFF_LEN];  //发送缓冲区
        unsigned short check_Buff[MAX_BUFF_LEN]; //检验和缓冲区
        //填充IP首部
        ipHeader.ver_ihl = (IPVER << 4 | sizeof(ipHeader) / sizeof(unsigned long));
        ipHeader.tos = (UCHAR)0;
        ipHeader.tlen = htons((unsigned short)sizeof(ipHeader) + sizeof(tcpHeader) + sizeof(CustomerData));
        ipHeader.identification = 0;       //16位标识
        ipHeader.flags_fo = 0; //3位标志位
        ipHeader.ttl = 128; //8位生存时间
        ipHeader.proto = IPPROTO_UDP; //协议类型
        ipHeader.crc = 0; //检验和暂时为0
        ipHeader.saddr = inet_addr(g_pcSrcIP);  //32位源IP地址
        ipHeader.daddr = inet_addr(g_pcDstIP);    //32位目的IP地址

        //计算IP头部检验和
        memset(check_Buff, 0, MAX_BUFF_LEN);
        memcpy(check_Buff, &ipHeader, sizeof(ip_header));
        ipHeader.crc = checksum(check_Buff, sizeof(ip_header));

        //构造TCP伪首部
        psdHeader.saddr = ipHeader.saddr;
        psdHeader.daddr = ipHeader.daddr;
        psdHeader.mbz = 0;
        psdHeader.ptcl = ipHeader.proto;
        psdHeader.tcpl = htons(sizeof(tcp_header) + sizeof(CustomerData));

        //填充TCP首部
        tcpHeader.dport = htons(DSTPORT); //16位目的端口号
        tcpHeader.sport = htons(SRCPORT); //16位源端口号
        tcpHeader.sNo = 0;                         //SYN序列号
        tcpHeader.cNo = 0;                         //ACK序列号置为0
        //TCP长度和保留位
        tcpHeader.fo_flags = (sizeof(tcpHeader) / sizeof(unsigned long) << 12 | 0);
        tcpHeader.fo_flags |= TCP_FLAG_SHORT_SYN; //标志位
        tcpHeader.wnd = htons((unsigned short)16384);     //窗口大小
        tcpHeader.urgp = 0;                            //偏移大小   
        tcpHeader.crc = 0;                            //检验和暂时填为0

        //计算TCP校验和
        memset(check_Buff, 0, MAX_BUFF_LEN);
        memcpy(check_Buff, &psdHeader, sizeof(psdHeader));
        memcpy(check_Buff + sizeof(psdHeader), &tcpHeader, sizeof(tcpHeader));
        memcpy(check_Buff + sizeof(psd_header) + sizeof(tcp_header), (const void*)&data, sizeof(CustomerData));
        tcpHeader.crc = checksum(check_Buff, sizeof(psd_header) + sizeof(tcp_header) + sizeof(CustomerData));

        //填充发送缓冲区
        memset(Sendto_Buff, 0, MAX_BUFF_LEN);
        memcpy(Sendto_Buff, &ipHeader, sizeof(ip_header));
        memcpy(Sendto_Buff + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
        memcpy(Sendto_Buff + sizeof(ip_header) + sizeof(tcp_header), (const void*)&data, sizeof(CustomerData));
        int datasize = sizeof(ip_header) + sizeof(tcp_header) + sizeof(CustomerData);
        //发送数据报的目的地址
        SOCKADDR_IN dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(g_pcDstIP);
        dest.sin_port = htons(DSTPORT);
        int ret = sendto(sock, Sendto_Buff, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));
        if (ret == SOCKET_ERROR)
        {
            printf("send error!:%d\n", WSAGetLastError());
            continue;
        }
        else
            printf("send ok!\n");

        //接收服务器返回的数据
        //char recvBuf[MAX_BUFF_LEN] = {};
        //int nLen = recv(sock, recvBuf, sizeof(CustomerDataHeader), 0);
        //CustomerDataHeader* header = (CustomerDataHeader*)recvBuf;
        //if (nLen <= 0) {
        //    printf("Received message invalid!\n");
        //    break;
        //}

        ////处理请求
        //nLen = recv(sock, recvBuf + sizeof(CustomerDataHeader), sizeof(CustomerData) - sizeof(CustomerDataHeader), 0);
        //CustomerData* pData = (CustomerData*)recvBuf;
        ////接收到有效数据
        //if (nLen > 0) {
        //    printf("Receive server message, length:%d, message: %s\n", pData->dataLen, pData->data);
        //}
        //else {
        //    printf("Received message invalid!\n");
        //}
    }

}

int main()
{
    WORD ver = MAKEWORD(2, 2);
    WSADATA dat;
    WSAStartup(ver, &dat);

    //建立windows socket
    //建立面向数据流的TCP ipv4 socket
    SOCKET sock;
    if ((sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
    {
        printf("Socket Setup Error! : %d\n", WSAGetLastError());
        getchar();
        return false;
    }
    BOOL flag = TRUE;//不能用bool
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) == SOCKET_ERROR)
    {
        printf("setsockopt IP_HDRINCL error!\n");
        return false;
    }
    int nTimeOver = 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOver, sizeof(nTimeOver)) == SOCKET_ERROR)
    {
        printf("setsockopt SO_SNDTIMEO error!\n");
        return false;
    }

    //连接服务器
    //sockaddr_in sin = {};
    //sin.sin_family = AF_INET;
    ////要连接的服务器端口
    //sin.sin_port = htons(SERVER_PORT);
    ////要连接的服务器ip地址
    //sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    //int ret = connect(sock, (sockaddr*)&sin, sizeof(sockaddr_in));
    //if (SOCKET_ERROR == ret) {
    //    printf("Failed to connect to server!\n");
    //}
    //else {
    //    printf("Connect to server success!\n");
    //}

    //启动用户输入线程
    std::thread t(cmdThread, sock);
    t.detach();//分离主线程与输入线程

    while (g_bOnRun) {
    }

    //关闭socket
    closesocket(sock);

    WSACleanup();

    printf("client exit, task terminate!\n");

    getchar();
    getchar();

    return 0;
}




