// sniffer.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
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


//����windows�����µ�winpcap dll
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

//�����
int sniffer()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
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

    //�����Ƿ�����Ĭ�Ϲ���������Ĭ�Ϲ�������Ҫ�����ڱ�����  �����Ѿ�����Ҫ��  ����ʹ��server  ֱ����2
    //���øù������Ա��ڹ۲챾��Ŀ�е�server��client֮��Ľ���
    //������Ҳ���ԣ���ô���о����ı��ػػ����ݰ�������
    int nEnableFiler = 0;
    printf("Do you want to use default filter: ip=127.0.0.1 and port=4567(1 = yes, other any number = no):\n");
    scanf("%d", &nEnableFiler);

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

    /* ������������ץȡ���߰���ʽ */
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

    //�ж���ѡ�������Ƿ��Ǳ��ػػ�������
    bool bForLoopBack = false;
    if (NULL != strstr(d->description, "LoopBack")) {
        bForLoopBack = true;
    }

    pcap_freealldevs(alldevs);

    //���ð�������
    if (1 == nEnableFiler) {
        bpf_u_int32 NetMask = 0xffffff;
        struct bpf_program fcode;
        //���������
        if (pcap_compile(adhandle, &fcode, "ip host 127.0.0.1 and tcp port 4567", 1, NetMask) < 0)
        {
            printf("\nError compiling filter: wrong syntax.\n");

            pcap_close(adhandle);
            return -1;
        }

        //���ù�����
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            printf("\nError setting the filter\n");

            pcap_close(adhandle);
            return -2;
        }
    }

    /*����ģʽ����־�ļ�*/
    FILE* f = fopen("sniffer.log", "a+");
    if (!f) {
        printf("Failed to open log file!Will NO log to file!\n");
    }

    /* ��ʼץ�� */
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {

        if (res == 0)
            /* ��ʱ */
            continue;

        /* ���ץ���İ� */

        u_int ip_len;
        u_short sport, dport;
        /* ���IP���ݰ�ͷ����λ�� */
        ip_header *ih = NULL;
        if (bForLoopBack) {
            ih = (ip_header *)(pkt_data + 4);//�ػ�
            ip_len = 20;
        }
        else {
            ih = (ip_header *)(pkt_data + 14);//14����̫��֡ͷ
            ip_len = (ih->ver_ihl & 0xf) * 4;
        }
        /* ���TCP�ײ���λ�� */
        tcp_header *th = (tcp_header *)((u_char*)ih + ip_len);
        /* �������ֽ�����ת���������ֽ����� */
        sport = ntohs(th->sport);
        dport = ntohs(th->dport);

        /* ��ӡIP��ַ��TCP�˿� */
        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;
        /* ��ʱ���ת���ɿ�ʶ��ģʽ */
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        //��ӡ������̨
        in_addr saddr;
        saddr.S_un.S_addr = ih->saddr;
        in_addr daddr;
        daddr.S_un.S_addr = ih->daddr;
        printf("%s,%.6d len:%d, %s:%d -> %s:%d, flags:[%s]\n",
            timestr, header->ts.tv_usec, header->len,
            inet_ntoa(saddr),sport, inet_ntoa(daddr),dport,
            GetTCPFlags(ntohs(th->fo_flags)));
        //�������־�ļ�
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



