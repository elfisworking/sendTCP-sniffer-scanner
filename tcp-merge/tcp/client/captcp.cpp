// customTCP.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"

//#ifdef _MSC_VER
//#define _CRT_SECURE_NO_WARNINGS
//#endif
//
#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#include <pcap.h>
//#include <stdio.h>
//#include <tchar.h>
//
//#include <Winsock2.h>
//#pragma comment(lib, "ws2_32.lib")

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#ifdef WIN32
#include <tchar.h>
#endif
#include <Winsock2.h>
#pragma comment(lib, "ws2_32.lib")




/*                       IP报文格式
0            8           16                        32
+------------+------------+-------------------------+
| ver + hlen |  服务类型  |         总长度          |
+------------+------------+----+--------------------+
|           标识位        |flag|   分片偏移(13位)   |
+------------+------------+----+--------------------+
|  生存时间  | 高层协议号 |       首部校验和        |
+------------+------------+-------------------------+
|                   源 IP 地址                      |
+---------------------------------------------------+
|                  目的 IP 地址                     |
+---------------------------------------------------+
*/


struct IP_HEADER
{
    byte versionAndHeader;
    byte serviceType;
    byte totalLen[2];
    byte seqNumber[2];
    byte flagAndFragPart[2];
    byte ttl;
    byte hiProtovolType;
    byte headerCheckSum[2];
    byte srcIpAddr[4];
    byte dstIpAddr[4];
};

/*
                     TCP 报文
0                       16                       32
+------------------------+-------------------------+
|      源端口地址        |      目的端口地址       |
+------------------------+-------------------------+
|                      序列号                      |
+--------------------------------------------------+
|                      确认号                      |
+------+--------+--------+-------------------------+
|HLEN/4| 保留位 |控制位/6|         窗口尺寸        |
+------+--------+--------+-------------------------+
|         校验和         |         应急指针        |
+------------------------+-------------------------+
*/

struct TCP_HEADER
{
    byte srcPort[2];
    byte dstPort[2];
    byte seqNumber[4];
    byte ackNumber[4];
    byte headLen;
    byte contrl;
    byte wndSize[2];
    byte checkSum[2];
    byte uragentPtr[2];
};
//伪TCP头部
struct PSDTCP_HEADER
{
    byte srcIpAddr[4];     //Source IP address; 32 bits
    byte dstIpAddr[4];     //Destination IP address; 32 bits 
    byte padding;          //padding
    byte protocol;         //Protocol; 8 bits
    byte tcpLen[2];        //TCP length; 16 bits
};
//以太帧头部
struct ETHERNET_HEADER
{
    byte dstMacAddr[6];
    byte srcMacAddr[6];
    byte ethernetType[2];
};


char *FormatIpAddr(unsigned uIpAddr, char szIp[])
{
    IN_ADDR addr;
    addr.S_un.S_addr = uIpAddr;

    strcpy(szIp, inet_ntoa(addr));
    return szIp;
}

//计算校验和
unsigned short CheckSum(unsigned short packet[], int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *packet++;
        size -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR*)packet;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);  //将高的16位与低的16位相加
    cksum += (cksum >> 16);//将进位到高16位的与低16的相加

    return (USHORT)(~cksum); //然后取反
}
//处理包
void HandlePacketCallBack(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)
{    //本地端口
    unsigned short localPort = *(unsigned short *)param;
    //接收到的包的以太网帧头
    ETHERNET_HEADER *pEthHeader = (ETHERNET_HEADER *)recvPacket;
    if (*((unsigned short *)(pEthHeader->ethernetType)) != htons(0x0800)) return; //过滤掉非IP数据包
    //接收到的包IP数据头
    IP_HEADER *pIpHeader = (IP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER));
    if (pIpHeader->hiProtovolType != 0x06) return; //过滤掉非TCP数据包
    //接收到的包的TCP包头
    TCP_HEADER *pTcpHeader = (TCP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));
    if (*(unsigned short *)(pTcpHeader->dstPort) != htons(localPort)) return; //过滤掉不是自己的TCP数据包

    //////////////////////////////////////////////////////////////////////
    //准备填充数据包，以给服务器进一步的响应，完成三次握手
    //填充IP数据包首部
    IP_HEADER ipHeader;
    memset(&ipHeader, 0, sizeof ipHeader);
    unsigned char versionAndLen = 0x04;
    versionAndLen <<= 4;
    versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度

    ipHeader.versionAndHeader = versionAndLen;
    *(unsigned short *)ipHeader.totalLen = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));

    ipHeader.ttl = 0xFF;
    ipHeader.hiProtovolType = 0x06;
	//将发送和接收方Ip地址反向
    memcpy(ipHeader.srcIpAddr, pIpHeader->dstIpAddr, sizeof(unsigned int));
    memcpy(ipHeader.dstIpAddr, pIpHeader->srcIpAddr, sizeof(unsigned int));
	//校验ip数据头
    *(unsigned short *)(ipHeader.headerCheckSum) = CheckSum((unsigned short *)&ipHeader, sizeof ipHeader);

    ////////////////////////////////////////////////////////////////////
    unsigned int ack = ntohl(*(unsigned int *)(pTcpHeader->seqNumber));
    unsigned int seq = ntohl(*(unsigned int *)(pTcpHeader->ackNumber));
	//开始填充tcp头部
    TCP_HEADER tcpHeader;
    memset(&tcpHeader, 0, sizeof tcpHeader);
    *(unsigned short *)tcpHeader.srcPort = htons(localPort);
    *(unsigned short *)tcpHeader.dstPort = htons(80);
    *(unsigned int *)tcpHeader.seqNumber = htonl(seq);
    *(unsigned int *)tcpHeader.ackNumber = htonl(ack + 1);
    tcpHeader.headLen = 5 << 4;
    tcpHeader.contrl = 0x01 << 4; //
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);

    ////////////////////////////伪tcp头//////////////////////////////////
    PSDTCP_HEADER psdHeader;
    memset(&psdHeader, 0x00, sizeof psdHeader);//先置零
    psdHeader.protocol = 0x06;
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));
    memcpy(psdHeader.dstIpAddr, ipHeader.dstIpAddr, sizeof(unsigned int));//同理
    memcpy(psdHeader.srcIpAddr, ipHeader.srcIpAddr, sizeof(unsigned int));

    byte psdPacket[1024];
    memcpy(psdPacket, &psdHeader, sizeof psdHeader);
    memcpy(psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader);

    *(unsigned short *)tcpHeader.checkSum = CheckSum((unsigned short*)psdPacket, sizeof psdHeader + sizeof tcpHeader);
	//以太帧
    ETHERNET_HEADER ethHeader;
    memset(&ethHeader, 0, sizeof ethHeader);
    memcpy(ethHeader.dstMacAddr, pEthHeader->srcMacAddr, 6);
    memcpy(ethHeader.srcMacAddr, pEthHeader->dstMacAddr, 6);
    *(unsigned short *)ethHeader.ethernetType = htons(0x0800);
	//包的分装
    byte packet[1024];
    memset(packet, 0, sizeof packet);

    memcpy(packet, &ethHeader, sizeof ethHeader);
    memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);
    memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);

    int size = sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader;

    pcap_t *handle = (pcap_t*)(param + sizeof(unsigned short));

    char srcIp[32], dstIp[32];
    byte ctrl = pTcpHeader->contrl & 0x3F;
    switch (ctrl)
    {
    case 0x01 << 1: //syn
        break;
        /*case 0x01 << 4: //ack
            puts("收到ack");
            break;*/
    case ((0x01 << 4) | (0x01 << 1)): //syn+ack

        FormatIpAddr(*(unsigned int *)(pIpHeader->srcIpAddr), srcIp);
        FormatIpAddr(*(unsigned int *)(pIpHeader->dstIpAddr), dstIp);
        printf("%-16s ---SYN + ACK--> %-16s\n", srcIp, dstIp);

        ///////////////////////////////////////////////////////////
        //回复服务器ACK，完成三次握手
        pcap_sendpacket(handle, packet, size);//发送数据包
        FormatIpAddr(*(unsigned int *)ipHeader.srcIpAddr, srcIp);
        FormatIpAddr(*(unsigned int *)ipHeader.dstIpAddr, dstIp);
        printf("%-16s ------ACK-----> %-16s\n", srcIp, dstIp);

        break;
    default:
        break;
    }
    return;
}

//加载windows环境下的winpcap dll
extern BOOL LoadNpcapDlls();

int captcp()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];  //存储错误信息
    /* 加载winpcap. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load winpcap\n");
        exit(1);
    }

    /* 获取所有网卡硬件列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /*打印硬件列表*/
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        getchar();//输入两个后退出
        getchar();
        return -1;
    }

    //用户选择需要嗅探或抓包的硬件
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* 释放硬件列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 跳到所选的网络适配器 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    srand(time(0));
    unsigned short srcPort = rand() % 65535;//6382;//随机源端口
    const char *lpszSrcIp = "192.168.43.36";//源ip地址，需要修改成当前运行时电脑网卡获取到的ip地址
    char lpszDstIp[32]/* = "180.97.33.107"*/;//目标ip地址
    printf("Enter the ip you want to send:\n");
    scanf("%s", lpszDstIp);
    const byte srcMac[] = { 0x68, 0x07, 0x15, 0xE5, 0x87, 0x47 };//主机mac，修改成本机mac
    const byte dstMac[] = { 0x48, 0x2c, 0xa0, 0x7a, 0x07, 0x62 }; //网关mac，修改成本机当前所在局域网网关的mac地址

    char szError[1024];//winpcap 设备连接错误缓冲区
    pcap_t *handle = pcap_open_live(d->name, 65536, 1, 1000, szError);
    if (NULL == handle) return 0;//打开设备产生错误

    //填充TCP包头
    TCP_HEADER tcpHeader;
    memset(&tcpHeader, 0, sizeof tcpHeader);
    *(unsigned short *)tcpHeader.srcPort = htons(srcPort);//源端口
    *(unsigned short *)tcpHeader.dstPort = htons(80);//目标端口默认80
    *(unsigned int *)tcpHeader.seqNumber = htonl(0x00);//SYN序列
    *(unsigned int *)tcpHeader.ackNumber = htonl(0x00);//ACK序列
    tcpHeader.headLen = 5 << 4;//默认TCP头部长度20字节
    tcpHeader.contrl = 1 << 1;//标志位
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);//窗口大小

    //伪TCP头部，用于计算校验和
    PSDTCP_HEADER psdHeader;
    memset(&psdHeader, 0, sizeof psdHeader);
    *(unsigned int *)psdHeader.dstIpAddr = inet_addr(lpszSrcIp);//目标ip地址
    *(unsigned int *)psdHeader.srcIpAddr = inet_addr(lpszDstIp);//源ip地址
    psdHeader.protocol = 0x06;//协议，6即为PROTOCOL_TCP
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));//长度
	//将伪tcp头与tcp相连接
    byte psdPacket[1024];
    memset(psdPacket, 0, sizeof psdPacket);
    memcpy(psdPacket, &psdHeader, sizeof psdHeader);
    memcpy(psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader);

    *(unsigned short *)tcpHeader.checkSum = CheckSum((unsigned short*)psdPacket, sizeof psdHeader + sizeof tcpHeader);//计算校验和

    //填充IP首部
    IP_HEADER ipHeader;
    memset(&ipHeader, 0, sizeof ipHeader);
    unsigned char versionAndLen = 0x04;//ipv4
    versionAndLen <<= 4;
    versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度

    ipHeader.versionAndHeader = versionAndLen;
    *(unsigned short *)ipHeader.totalLen = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));//ip首部长度

    ipHeader.ttl = 0xFF;//存活时间
    ipHeader.hiProtovolType = 0x06;//协议类型

    *(unsigned int *)(ipHeader.srcIpAddr) = inet_addr(lpszSrcIp);//源ip地址
    *(unsigned int *)(ipHeader.dstIpAddr) = inet_addr(lpszDstIp);//目标ip地址
    *(unsigned short *)(ipHeader.headerCheckSum) = CheckSum((unsigned short *)&ipHeader, sizeof ipHeader);//校验和

    //以太网帧头
    ETHERNET_HEADER ethHeader;
    memset(&ethHeader, 0, sizeof ethHeader);
    memcpy(ethHeader.dstMacAddr, dstMac, 6);//目标mac地址
    memcpy(ethHeader.srcMacAddr, srcMac, 6);//源mac地址
    *(unsigned short *)ethHeader.ethernetType = htons(0x0800);//以太网类型

    byte packet[1024];
    memset(packet, 0, sizeof packet);
    //准备待发送的SYN包
    memcpy(packet, &ethHeader, sizeof ethHeader);
    memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);
    memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);
    //发送SYN包
    int size = sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader;
    pcap_sendpacket(handle, packet, size);
    printf("%-16s ------SYN-----> %-16s\n", lpszSrcIp, lpszDstIp);

    if (NULL == handle)
    {
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
        return 0;
    }
    byte param[1024];
    memset(param, 0x00, sizeof param);
    memcpy(param, &srcPort, sizeof srcPort);
    memcpy(param + sizeof srcPort, handle, 512);
    //等待服务器响应并处理
    pcap_loop(handle, -1, HandlePacketCallBack, param);
    //关闭设备句柄
    pcap_close(handle);
    return 0;
}

