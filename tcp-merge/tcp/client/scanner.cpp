// scanner.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <WinSock2.h>
#include <stdio.h>
#include <thread>

#define PRINT_ALL_FAILURE 0

#define SCANNER_THREAD_CNT 256//扫描线程数

typedef struct scannerParam {
    unsigned long ip;
    unsigned int port_from;
    unsigned int port_to;
}scannerParam;

DWORD WINAPI scannerThread_win(LPVOID lpparam)
{
    scannerParam* param = (scannerParam*)lpparam;
    //连接服务器
    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    //要连接的服务器ip地址
    sin.sin_addr.S_un.S_addr = param->ip;

    //建立windows socket
    //建立面向数据流的TCP ipv4 socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (INVALID_SOCKET == sock) {
        printf("Failed to create socket!\n");
        return -1;
    }
    printf("new thread for: ip=%s, port from:%d to %d\n", inet_ntoa(sin.sin_addr), param->port_from, param->port_to);

    for (unsigned int port = param->port_from; port < param->port_to; port++) {
        //要连接的服务器端口
        sin.sin_port = htons(port);
        int ret = connect(sock, (sockaddr*)&sin, sizeof(sockaddr_in));
        if (SOCKET_ERROR == ret) {
#if PRINT_ALL_FAILURE
            printf("Failed to connect port:%d.\n", port);
#endif
            continue;
        }
        //读写描述符
        fd_set fdRead;
        FD_ZERO(&fdRead);
        FD_SET(sock, &fdRead);
        fd_set fdWrite;
        FD_ZERO(&fdWrite);
        FD_SET(sock, &fdWrite);
        timeval t = { 0 , 0 };
        //select模型
        ret = select(sock, &fdRead, &fdWrite, NULL, &t);
        if (ret >= 0) {//有效连接
            printf("****TCP service opened on port:%d @ret=%d.\n", port, ret);
        }
        //关闭socket
        closesocket(sock);
    }
    return 0;
}


int scanner()
{
    WORD ver = MAKEWORD(2, 2);
    WSADATA dat;
    WSAStartup(ver, &dat);

    //用户输入请求命令
    char cmdBuf[64] = {};
    printf("Please input the ip you want to scan:\n");
    scanf("%s", cmdBuf);
    printf("scanning...\n");

    unsigned long serverIP = inet_addr(cmdBuf);

    //启动扫描线程
    unsigned int port_interval = 65535 / SCANNER_THREAD_CNT;//端口总数65535
    unsigned int port_rest = 65535 % SCANNER_THREAD_CNT;
    unsigned int base = port_rest * (port_interval + 1);//尽量将待扫描端口数量平均分配

    //分配待扫描端口，并创建线程开始执行
    HANDLE threads[SCANNER_THREAD_CNT];
    scannerParam params[SCANNER_THREAD_CNT];
    DWORD threadIds[SCANNER_THREAD_CNT];
    for (unsigned int i = 0; i < port_rest; i++) {//前一部分端口，每个线程分配端口数量为port_interval+1
        params[i].ip = serverIP;
        params[i].port_from = i * (port_interval + 1);
        params[i].port_to = (i + 1)*(port_interval + 1);

        threads[i] = CreateThread(NULL, 0, scannerThread_win, &params[i], 0, &threadIds[i]);
    }
    for (int i = port_rest; i < SCANNER_THREAD_CNT; i++) {//后一部分端口，每个线程分配端口数量为port_interval
        params[i].ip = serverIP;
        params[i].port_from = base + (i - port_rest) *port_interval;
        params[i].port_to = base + (i - port_rest + 1)*port_interval;

        threads[i] = CreateThread(NULL, 0, scannerThread_win, &params[i], 0, &threadIds[i]);
    }

    //等待各线程执行完毕
    //WaitForMultipleObjects可等待句柄数有上限
    int waitNumbers = SCANNER_THREAD_CNT / MAXIMUM_WAIT_OBJECTS + 1;
    for (int i = 0; i < waitNumbers; ++i) {
        WaitForMultipleObjects((i == waitNumbers - 1) ? (SCANNER_THREAD_CNT - i * MAXIMUM_WAIT_OBJECTS) : MAXIMUM_WAIT_OBJECTS,
            threads + i * MAXIMUM_WAIT_OBJECTS, TRUE, INFINITE);
    }

    WSACleanup();

    printf("scanner finish!\n");

    getchar();
    getchar();

    return 0;
}



