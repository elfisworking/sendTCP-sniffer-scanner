// customTCP.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
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




/*                       IP���ĸ�ʽ
0            8           16                        32
+------------+------------+-------------------------+
| ver + hlen |  ��������  |         �ܳ���          |
+------------+------------+----+--------------------+
|           ��ʶλ        |flag|   ��Ƭƫ��(13λ)   |
+------------+------------+----+--------------------+
|  ����ʱ��  | �߲�Э��� |       �ײ�У���        |
+------------+------------+-------------------------+
|                   Դ IP ��ַ                      |
+---------------------------------------------------+
|                  Ŀ�� IP ��ַ                     |
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
                     TCP ����
0                       16                       32
+------------------------+-------------------------+
|      Դ�˿ڵ�ַ        |      Ŀ�Ķ˿ڵ�ַ       |
+------------------------+-------------------------+
|                      ���к�                      |
+--------------------------------------------------+
|                      ȷ�Ϻ�                      |
+------+--------+--------+-------------------------+
|HLEN/4| ����λ |����λ/6|         ���ڳߴ�        |
+------+--------+--------+-------------------------+
|         У���         |         Ӧ��ָ��        |
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
//αTCPͷ��
struct PSDTCP_HEADER
{
    byte srcIpAddr[4];     //Source IP address; 32 bits
    byte dstIpAddr[4];     //Destination IP address; 32 bits 
    byte padding;          //padding
    byte protocol;         //Protocol; 8 bits
    byte tcpLen[2];        //TCP length; 16 bits
};
//��̫֡ͷ��
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

//����У���
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
    cksum = (cksum >> 16) + (cksum & 0xffff);  //���ߵ�16λ��͵�16λ���
    cksum += (cksum >> 16);//����λ����16λ�����16�����

    return (USHORT)(~cksum); //Ȼ��ȡ��
}
//�����
void HandlePacketCallBack(unsigned char *param, const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)
{    //���ض˿�
    unsigned short localPort = *(unsigned short *)param;
    //���յ��İ�����̫��֡ͷ
    ETHERNET_HEADER *pEthHeader = (ETHERNET_HEADER *)recvPacket;
    if (*((unsigned short *)(pEthHeader->ethernetType)) != htons(0x0800)) return; //���˵���IP���ݰ�
    //���յ��İ�IP����ͷ
    IP_HEADER *pIpHeader = (IP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER));
    if (pIpHeader->hiProtovolType != 0x06) return; //���˵���TCP���ݰ�
    //���յ��İ���TCP��ͷ
    TCP_HEADER *pTcpHeader = (TCP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));
    if (*(unsigned short *)(pTcpHeader->dstPort) != htons(localPort)) return; //���˵������Լ���TCP���ݰ�

    //////////////////////////////////////////////////////////////////////
    //׼��������ݰ����Ը���������һ������Ӧ�������������
    //���IP���ݰ��ײ�
    IP_HEADER ipHeader;
    memset(&ipHeader, 0, sizeof ipHeader);
    unsigned char versionAndLen = 0x04;
    versionAndLen <<= 4;
    versionAndLen |= sizeof ipHeader / 4; //�汾 + ͷ����

    ipHeader.versionAndHeader = versionAndLen;
    *(unsigned short *)ipHeader.totalLen = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));

    ipHeader.ttl = 0xFF;
    ipHeader.hiProtovolType = 0x06;
	//�����ͺͽ��շ�Ip��ַ����
    memcpy(ipHeader.srcIpAddr, pIpHeader->dstIpAddr, sizeof(unsigned int));
    memcpy(ipHeader.dstIpAddr, pIpHeader->srcIpAddr, sizeof(unsigned int));
	//У��ip����ͷ
    *(unsigned short *)(ipHeader.headerCheckSum) = CheckSum((unsigned short *)&ipHeader, sizeof ipHeader);

    ////////////////////////////////////////////////////////////////////
    unsigned int ack = ntohl(*(unsigned int *)(pTcpHeader->seqNumber));
    unsigned int seq = ntohl(*(unsigned int *)(pTcpHeader->ackNumber));
	//��ʼ���tcpͷ��
    TCP_HEADER tcpHeader;
    memset(&tcpHeader, 0, sizeof tcpHeader);
    *(unsigned short *)tcpHeader.srcPort = htons(localPort);
    *(unsigned short *)tcpHeader.dstPort = htons(80);
    *(unsigned int *)tcpHeader.seqNumber = htonl(seq);
    *(unsigned int *)tcpHeader.ackNumber = htonl(ack + 1);
    tcpHeader.headLen = 5 << 4;
    tcpHeader.contrl = 0x01 << 4; //
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);

    ////////////////////////////αtcpͷ//////////////////////////////////
    PSDTCP_HEADER psdHeader;
    memset(&psdHeader, 0x00, sizeof psdHeader);//������
    psdHeader.protocol = 0x06;
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));
    memcpy(psdHeader.dstIpAddr, ipHeader.dstIpAddr, sizeof(unsigned int));//ͬ��
    memcpy(psdHeader.srcIpAddr, ipHeader.srcIpAddr, sizeof(unsigned int));

    byte psdPacket[1024];
    memcpy(psdPacket, &psdHeader, sizeof psdHeader);
    memcpy(psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader);

    *(unsigned short *)tcpHeader.checkSum = CheckSum((unsigned short*)psdPacket, sizeof psdHeader + sizeof tcpHeader);
	//��̫֡
    ETHERNET_HEADER ethHeader;
    memset(&ethHeader, 0, sizeof ethHeader);
    memcpy(ethHeader.dstMacAddr, pEthHeader->srcMacAddr, 6);
    memcpy(ethHeader.srcMacAddr, pEthHeader->dstMacAddr, 6);
    *(unsigned short *)ethHeader.ethernetType = htons(0x0800);
	//���ķ�װ
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
            puts("�յ�ack");
            break;*/
    case ((0x01 << 4) | (0x01 << 1)): //syn+ack

        FormatIpAddr(*(unsigned int *)(pIpHeader->srcIpAddr), srcIp);
        FormatIpAddr(*(unsigned int *)(pIpHeader->dstIpAddr), dstIp);
        printf("%-16s ---SYN + ACK--> %-16s\n", srcIp, dstIp);

        ///////////////////////////////////////////////////////////
        //�ظ�������ACK�������������
        pcap_sendpacket(handle, packet, size);//�������ݰ�
        FormatIpAddr(*(unsigned int *)ipHeader.srcIpAddr, srcIp);
        FormatIpAddr(*(unsigned int *)ipHeader.dstIpAddr, dstIp);
        printf("%-16s ------ACK-----> %-16s\n", srcIp, dstIp);

        break;
    default:
        break;
    }
    return;
}

//����windows�����µ�winpcap dll
extern BOOL LoadNpcapDlls();

int captcp()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];  //�洢������Ϣ
    /* ����winpcap. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load winpcap\n");
        exit(1);
    }

    /* ��ȡ��������Ӳ���б� */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /*��ӡӲ���б�*/
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
        getchar();//�����������˳�
        getchar();
        return -1;
    }

    //�û�ѡ����Ҫ��̽��ץ����Ӳ��
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* �ͷ�Ӳ���б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ������ѡ������������ */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    srand(time(0));
    unsigned short srcPort = rand() % 65535;//6382;//���Դ�˿�
    const char *lpszSrcIp = "192.168.43.36";//Դip��ַ����Ҫ�޸ĳɵ�ǰ����ʱ����������ȡ����ip��ַ
    char lpszDstIp[32]/* = "180.97.33.107"*/;//Ŀ��ip��ַ
    printf("Enter the ip you want to send:\n");
    scanf("%s", lpszDstIp);
    const byte srcMac[] = { 0x68, 0x07, 0x15, 0xE5, 0x87, 0x47 };//����mac���޸ĳɱ���mac
    const byte dstMac[] = { 0x48, 0x2c, 0xa0, 0x7a, 0x07, 0x62 }; //����mac���޸ĳɱ�����ǰ���ھ��������ص�mac��ַ

    char szError[1024];//winpcap �豸���Ӵ��󻺳���
    pcap_t *handle = pcap_open_live(d->name, 65536, 1, 1000, szError);
    if (NULL == handle) return 0;//���豸��������

    //���TCP��ͷ
    TCP_HEADER tcpHeader;
    memset(&tcpHeader, 0, sizeof tcpHeader);
    *(unsigned short *)tcpHeader.srcPort = htons(srcPort);//Դ�˿�
    *(unsigned short *)tcpHeader.dstPort = htons(80);//Ŀ��˿�Ĭ��80
    *(unsigned int *)tcpHeader.seqNumber = htonl(0x00);//SYN����
    *(unsigned int *)tcpHeader.ackNumber = htonl(0x00);//ACK����
    tcpHeader.headLen = 5 << 4;//Ĭ��TCPͷ������20�ֽ�
    tcpHeader.contrl = 1 << 1;//��־λ
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);//���ڴ�С

    //αTCPͷ�������ڼ���У���
    PSDTCP_HEADER psdHeader;
    memset(&psdHeader, 0, sizeof psdHeader);
    *(unsigned int *)psdHeader.dstIpAddr = inet_addr(lpszSrcIp);//Ŀ��ip��ַ
    *(unsigned int *)psdHeader.srcIpAddr = inet_addr(lpszDstIp);//Դip��ַ
    psdHeader.protocol = 0x06;//Э�飬6��ΪPROTOCOL_TCP
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));//����
	//��αtcpͷ��tcp������
    byte psdPacket[1024];
    memset(psdPacket, 0, sizeof psdPacket);
    memcpy(psdPacket, &psdHeader, sizeof psdHeader);
    memcpy(psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader);

    *(unsigned short *)tcpHeader.checkSum = CheckSum((unsigned short*)psdPacket, sizeof psdHeader + sizeof tcpHeader);//����У���

    //���IP�ײ�
    IP_HEADER ipHeader;
    memset(&ipHeader, 0, sizeof ipHeader);
    unsigned char versionAndLen = 0x04;//ipv4
    versionAndLen <<= 4;
    versionAndLen |= sizeof ipHeader / 4; //�汾 + ͷ����

    ipHeader.versionAndHeader = versionAndLen;
    *(unsigned short *)ipHeader.totalLen = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));//ip�ײ�����

    ipHeader.ttl = 0xFF;//���ʱ��
    ipHeader.hiProtovolType = 0x06;//Э������

    *(unsigned int *)(ipHeader.srcIpAddr) = inet_addr(lpszSrcIp);//Դip��ַ
    *(unsigned int *)(ipHeader.dstIpAddr) = inet_addr(lpszDstIp);//Ŀ��ip��ַ
    *(unsigned short *)(ipHeader.headerCheckSum) = CheckSum((unsigned short *)&ipHeader, sizeof ipHeader);//У���

    //��̫��֡ͷ
    ETHERNET_HEADER ethHeader;
    memset(&ethHeader, 0, sizeof ethHeader);
    memcpy(ethHeader.dstMacAddr, dstMac, 6);//Ŀ��mac��ַ
    memcpy(ethHeader.srcMacAddr, srcMac, 6);//Դmac��ַ
    *(unsigned short *)ethHeader.ethernetType = htons(0x0800);//��̫������

    byte packet[1024];
    memset(packet, 0, sizeof packet);
    //׼�������͵�SYN��
    memcpy(packet, &ethHeader, sizeof ethHeader);
    memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);
    memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);
    //����SYN��
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
    //�ȴ���������Ӧ������
    pcap_loop(handle, -1, HandlePacketCallBack, param);
    //�ر��豸���
    pcap_close(handle);
    return 0;
}

