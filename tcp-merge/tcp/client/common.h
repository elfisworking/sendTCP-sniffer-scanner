#pragma once
#include <Windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdio.h>



#define SERVER_PORT 4567
#define CLIENT_PORT 34567

const static char* g_pcSrcIP = "127.0.0.1"/*"10.0.0.13"*/;
const static char* g_pcDstIP = "127.0.0.1"/*"39.105.119.70"*/;
#define SRCPORT 34567//34567
#define DSTPORT 4567//22

#define IPVER   4           //IPЭ��Ԥ��
#define MSG_MAX_LENGTH 512
#define MAX_BUFF_LEN 65535  //���ͻ�������󳤶�
//--------------------------------------------------------------------------------------------
//--Ӧ�ò����ݰ�����
//--------------------------------------------------------------------------------------------
//������Ϣͷ��ָ������
typedef struct CustomerDataHeader {
    CustomerDataHeader() : dataLen(0) {}
    CustomerDataHeader(int srcDataLen) {
        dataLen = srcDataLen;
    }
    //���ݳ���
    int dataLen;
}CustomerDataHeader;
//��֧���ı���Ϣ�������Զ���ṹ��Ϣ���մ˰���
typedef struct CustomerData : public CustomerDataHeader {
    CustomerData() :CustomerDataHeader(0) {}
    CustomerData(const char* srcData) {
        if (!srcData) {
            dataLen = 0;
        }
        else {
            dataLen = strlen(srcData) + 1;
            memset(data, 0, MSG_MAX_LENGTH);
            strcpy(data, srcData);
        }
    }
    void clear() {
        memset(data, 0, MSG_MAX_LENGTH);
        dataLen = 0;
    }
    //char* data;
    char data[MSG_MAX_LENGTH];
}CustomerData;

//--------------------------------------------------------------------------------------------
//--TCP/IPЭ������ݰ����嶨��
//--------------------------------------------------------------------------------------------
typedef struct psd_header //����TCPα�ײ������ڼ���У��͵�
{
    ULONG saddr;    //Դ��ַ
    ULONG daddr;    //Ŀ�ĵ�ַ
    UCHAR mbz;        //û��
    UCHAR ptcl;        //Э������
    USHORT tcpl;    //TCP����
}psd_header;


/* IPv4 �ײ� */
typedef struct ip_header {
    u_char      ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
    u_char      tos;            // ��������(Type of service) 
    u_short     tlen;           // �ܳ�(Total length) 
    u_short     identification; // ��ʶ(Identification)
    u_short     flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    u_char      ttl;            // ���ʱ��(Time to live)
    u_char      proto;          // Э��(Protocol)
    u_short     crc;            // �ײ�У���(Header checksum)
    //u_int       saddr;          // Դ��ַ(Source address)
    //u_int       daddr;          // Ŀ�ĵ�ַ(Destination address)
    u_long      saddr;          // Դ��ַ(Source address)
    u_long      daddr;          // Ŀ�ĵ�ַ(Destination address)
    u_int       op_pad;         // ѡ�������(Option + Padding)
}ip_header;


/* TCP ��־λ*/
#define TCP_FLAG_SHORT_FIN 0x1<<0
#define TCP_FLAG_SHORT_SYN 0x1<<1
#define TCP_FLAG_SHORT_RST 0x1<<2
#define TCP_FLAG_SHORT_PSH 0x1<<3
#define TCP_FLAG_SHORT_ACK 0x1<<4
#define TCP_FLAG_SHORT_URG 0x1<<5

#define TCP_FLAG_CNT 6

const static char* g_tcp_flags[TCP_FLAG_CNT] = {
    "FIN",
    "SYN",
    "RST",
    "PSH",
    "ACK",
    "URG",
};

inline const char* GetTCPFlags(u_short p_uflags) {
    static char strFlags[32];
    memset(strFlags, 0, 32);
    int nFlagCnt = 0;
    for (int i = 0; i < TCP_FLAG_CNT; i++) {
        if (p_uflags >> i & 0x1) {
            strncpy(strFlags + nFlagCnt * 4, g_tcp_flags[i], 3);
            nFlagCnt++;
            strFlags[4 * (nFlagCnt - 1) + 3] = ',';
        }
    }
    if (nFlagCnt > 0) {
        strFlags[4 * (nFlagCnt - 1) + 3] = '\0';
    }
    return strFlags;
}

/* TCP �ײ�*/
typedef struct tcp_header {
    u_short sport;          // Դ�˿�(Source port)
    u_short dport;          // Ŀ�Ķ˿�(Destination port)
    u_int   sNo;            // ���
    u_int   cNo;            // ȷ�Ϻ�
    u_short fo_flags;       // ����ƫ��4λ+6λ����+6λ��־λ(URG,ACK,PSH,RST,SYN,FIN)
    u_short wnd;            // ����
    u_short crc;            // У���(Checksum)
    u_short urgp;            // ����ָ��
    u_int   op_pad;         // ѡ�������(Option + Padding)
}tcp_header;

