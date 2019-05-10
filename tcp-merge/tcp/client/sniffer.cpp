// sniffer.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <pcap.h>
#ifdef WIN32
#include <tchar.h>
#include "common.h"


#pragma comment(lib, "ws2_32.lib")
#define LINE_LEN 16


//加载windows环境下的winpcap dll
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

//主入口
int sniffer()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
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

    //决定是否启用默认过滤器，该默认过滤器主要适用于本工程  现在已经不需要了  不再使用server  直接摁2
    //启用该过滤器以便于观察本项目中的server与client之间的交互
    //不启用也可以，那么会有巨量的本地回环数据包被捕获
    int nEnableFiler = 0;
    printf("Do you want to use default filter: ip=127.0.0.1 and port=4567(1 = yes, other any number = no):\n");
    scanf("%d", &nEnableFiler);

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

    /* 开启适配器，抓取在线包形式 */
    if ((adhandle = pcap_open_live(d->name,	// name of the device
        65536,			// portion of the packet to capture. 
                       // 65536 grants that the whole packet will be captured on all the MACs.
        1,				// promiscuous mode (nonzero means promiscuous)
        1000,			// read timeout
        errbuf			// error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    //判断所选适配器是否是本地回环适配器
    bool bForLoopBack = false;
    if (NULL != strstr(d->description, "LoopBack")) {
        bForLoopBack = true;
    }

    pcap_freealldevs(alldevs);

    //设置包过滤器
    if (1 == nEnableFiler) {
        bpf_u_int32 NetMask = 0xffffff;
        struct bpf_program fcode;
        //编译过滤器
        if (pcap_compile(adhandle, &fcode, "ip host 127.0.0.1 and tcp port 4567", 1, NetMask) < 0)
        {
            printf("\nError compiling filter: wrong syntax.\n");

            pcap_close(adhandle);
            return -1;
        }

        //设置过滤器
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            printf("\nError setting the filter\n");

            pcap_close(adhandle);
            return -2;
        }
    }

    /*附加模式打开日志文件*/
    FILE* f = fopen("sniffer.log", "a+");
    if (!f) {
        printf("Failed to open log file!Will NO log to file!\n");
    }

    /* 开始抓包 */
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {

        if (res == 0)
            /* 超时 */
            continue;

        /* 输出抓到的包 */

        u_int ip_len;
        u_short sport, dport;
        /* 获得IP数据包头部的位置 */
        ip_header *ih = NULL;
        if (bForLoopBack) {
            ih = (ip_header *)(pkt_data + 4);//回环
            ip_len = 20;
        }
        else {
            ih = (ip_header *)(pkt_data + 14);//14是以太网帧头
            ip_len = (ih->ver_ihl & 0xf) * 4;
        }
        /* 获得TCP首部的位置 */
        tcp_header *th = (tcp_header *)((u_char*)ih + ip_len);
        /* 将网络字节序列转换成主机字节序列 */
        sport = ntohs(th->sport);
        dport = ntohs(th->dport);

        /* 打印IP地址和TCP端口 */
        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;
        /* 将时间戳转换成可识别模式 */
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        //打印到控制台
        in_addr saddr;
        saddr.S_un.S_addr = ih->saddr;
        in_addr daddr;
        daddr.S_un.S_addr = ih->daddr;
        printf("%s,%.6d len:%d, %s:%d -> %s:%d, flags:[%s]\n",
            timestr, header->ts.tv_usec, header->len,
            inet_ntoa(saddr),sport, inet_ntoa(daddr),dport,
            GetTCPFlags(ntohs(th->fo_flags)));
        //输出至日志文件
        if (f) {
            fprintf(f, "%s,%.6d len:%d, %s:%d -> %s:%d, flags:[%s]\n",
                timestr, header->ts.tv_usec, header->len,
                inet_ntoa(saddr), sport, inet_ntoa(daddr), dport,
                GetTCPFlags(ntohs(th->fo_flags)));
        }
    }

    pcap_close(adhandle);
    if (f) {
        fclose(f);
    }
    return 0;
}



