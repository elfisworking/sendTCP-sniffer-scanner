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

#define IPVER   4           //IP协议预定
#define MSG_MAX_LENGTH 512
#define MAX_BUFF_LEN 65535  //发送缓冲区最大长度
//--------------------------------------------------------------------------------------------
//--应用层数据包定义
//--------------------------------------------------------------------------------------------
//定义消息头，指明长度
typedef struct CustomerDataHeader {
    CustomerDataHeader() : dataLen(0) {}
    CustomerDataHeader(int srcDataLen) {
        dataLen = srcDataLen;
    }
    //数据长度
    int dataLen;
}CustomerDataHeader;
//暂支持文本消息，其它自定义结构消息可照此办理
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
//--TCP/IP协议层数据包定义定义
//--------------------------------------------------------------------------------------------
typedef struct psd_header //定义TCP伪首部，用于计算校验和等
{
    ULONG saddr;    //源地址
    ULONG daddr;    //目的地址
    UCHAR mbz;        //没用
    UCHAR ptcl;        //协议类型
    USHORT tcpl;    //TCP长度
}psd_header;


/* IPv4 首部 */
typedef struct ip_header {
    u_char      ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char      tos;            // 服务类型(Type of service) 
    u_short     tlen;           // 总长(Total length) 
    u_short     identification; // 标识(Identification)
    u_short     flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char      ttl;            // 存活时间(Time to live)
    u_char      proto;          // 协议(Protocol)
    u_short     crc;            // 首部校验和(Header checksum)
    //u_int       saddr;          // 源地址(Source address)
    //u_int       daddr;          // 目的地址(Destination address)
    u_long      saddr;          // 源地址(Source address)
    u_long      daddr;          // 目的地址(Destination address)
    u_int       op_pad;         // 选项与填充(Option + Padding)
}ip_header;


/* TCP 标志位*/
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

/* TCP 首部*/
typedef struct tcp_header {
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_int   sNo;            // 序号
    u_int   cNo;            // 确认号
    u_short fo_flags;       // 数据偏移4位+6位保留+6位标志位(URG,ACK,PSH,RST,SYN,FIN)
    u_short wnd;            // 窗口
    u_short crc;            // 校验和(Checksum)
    u_short urgp;            // 紧急指针
    u_int   op_pad;         // 选项与填充(Option + Padding)
}tcp_header;

