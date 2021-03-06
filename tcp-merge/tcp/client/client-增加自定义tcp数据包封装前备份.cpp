// client.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#define WIN32_LEAN_AND_MEAN

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <WinSock2.h>

#include <stdio.h>

#include <thread>

#define SERVER_PORT 4567
#define MSG_MAX_LENGTH 512
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
    //char* data;
    char data[MSG_MAX_LENGTH];
}CustomerData;


int processor(SOCKET sock)
{
    //接收客户端的请求数据
    //服务端接收缓冲区
    char recvBuf[4096] = {};
    int nLen = recv(sock, recvBuf, sizeof(CustomerDataHeader), 0);
    CustomerDataHeader* header = (CustomerDataHeader*)recvBuf;
    if (nLen <= 0) {
        printf("Received message invalid!\n");
        return -1;
    }

    //处理请求
    nLen = recv(sock, recvBuf + sizeof(CustomerDataHeader), sizeof(CustomerData) - sizeof(CustomerDataHeader), 0);
    CustomerData* pData = (CustomerData*)recvBuf;
    //接收到有效数据
    if (nLen > 0) {
        printf("Receive server message, length:%d, message: %s\n", pData->dataLen, pData->data);
    }
    else {
        printf("Received message invalid!\n");
    }
    return 0;
}

extern int scanner();
extern int sniffer();

bool g_bOnRun = true;
//创建用户命令输入线程
void cmdThread(SOCKET sock)
{
    //用户输入请求命令
    while (true) {
        CustomerData data;
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
        //向服务器发送请求命令
        send(sock, (const char*)&data, sizeof(CustomerData), 0);
        //接收服务器返回的数据
        char recvBuf[4096] = {};
        int nLen = recv(sock, recvBuf, sizeof(CustomerDataHeader), 0);
        CustomerDataHeader* header = (CustomerDataHeader*)recvBuf;
        if (nLen <= 0) {
            printf("Received message invalid!\n");
            break;
        }

        //处理请求
        nLen = recv(sock, recvBuf + sizeof(CustomerDataHeader), sizeof(CustomerData) - sizeof(CustomerDataHeader), 0);
        CustomerData* pData = (CustomerData*)recvBuf;
        //接收到有效数据
        if (nLen > 0) {
            printf("Receive server message, length:%d, message: %s\n", pData->dataLen, pData->data);
        }
        else {
            printf("Received message invalid!\n");
        }
    }

}

int main()
{
    WORD ver = MAKEWORD(2, 2);
    WSADATA dat;
    WSAStartup(ver, &dat);

    //建立windows socket
    //建立面向数据流的TCP ipv4 socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (INVALID_SOCKET == sock) {
        printf("Failed to create socket！\n");
    }
    else {
        printf("Create socket success！\n");
    }

    //连接服务器
    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    //要连接的服务器端口
    sin.sin_port = htons(SERVER_PORT);
    //要连接的服务器ip地址
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    int ret = connect(sock, (sockaddr*)&sin, sizeof(sockaddr_in));
    if (SOCKET_ERROR == ret) {
        printf("Failed to connect to server!\n");
    }
    else {
        printf("Connect to server success!\n");
    }

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




