// server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <WinSock2.h>

#include <stdio.h>

#include <vector>

using std::vector;

vector<SOCKET> g_vecClients;

#define SERVER_PORT 4567
#define MSG_MAX_LENGTH 512

typedef struct CustomerDataHeader {
    CustomerDataHeader() : dataLen(0) {}
    CustomerDataHeader(int srcDataLen) {
        dataLen = srcDataLen;
    }
    //数据长度
    int dataLen;
}CustomerDataHeader;

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


int processor(SOCKET clientSock)
{
    //接收客户端的请求数据
    //服务端接收缓冲
    char recvBuf[4096] = {};
    int nLen = recv(clientSock, recvBuf, sizeof(CustomerDataHeader), 0);
    CustomerDataHeader* header = (CustomerDataHeader*)recvBuf;
    if (nLen <= 0) {
        printf("client <Socket = %d> exit, task terminate!\n", clientSock);
        return -1;
    }

    //处理请求
    nLen = recv(clientSock, recvBuf + sizeof(CustomerDataHeader), sizeof(CustomerData) - sizeof(CustomerDataHeader), 0);
    CustomerData* data = (CustomerData*)recvBuf;
    printf("Receive client <Socket = %d> message, length:%d, message: %s\n", clientSock, data->dataLen, data->data);

    CustomerData ret = { "Confirm Get Client Data!" };
    send(clientSock, (const char*)&ret, sizeof(CustomerData), 0);
    return 0;
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
    //绑定网络端口
    sockaddr_in sin = {};
    //IPv4
    sin.sin_family = AF_INET;
    //host to net unsigned short，网络字节序转换
    sin.sin_port = htons(SERVER_PORT);
    //本机所有ip均可提供服务
    sin.sin_addr.S_un.S_addr = INADDR_ANY;
    //绑定失败
    if (bind(sock, (sockaddr*)&sin, sizeof(sockaddr_in)) == SOCKET_ERROR) {
        printf("ERROR: Failed to bind port : %d\n", SERVER_PORT);
    }
    else {
        //绑定成功
        printf("Bind port %d success!\n", SERVER_PORT);
    }

    //监听端口
    if (listen(sock, 10) == SOCKET_ERROR) {
        printf("ERROR: Failed to listen port!\n");
    }
    else {
        printf("Listen port success!\n");
    }

    //循环接收客户端连接并发送数据
    while (true) {
        //BSD socket
        //socket set
        fd_set fdRead;
        fd_set fdWrite;
        fd_set fdExcept;

        //清空
        FD_ZERO(&fdRead);
        FD_ZERO(&fdWrite);
        FD_ZERO(&fdExcept);
        //将服务端socket加入集合
        FD_SET(sock, &fdRead);
        FD_SET(sock, &fdWrite);
        FD_SET(sock, &fdExcept);

        for (int n = g_vecClients.size() - 1; n >= 0; n--) {
            FD_SET(g_vecClients[n], &fdRead);
        }
        //nfds为fd_set集合中所有socket的范围（最大值加1），在windows中无意义
        timeval t = { 1, 0 };//查询后若无数据立即返回
        int nRet = select(sock + 1, &fdRead, &fdWrite, &fdExcept, &t);//interval为NULL，则为阻塞式
        if (nRet < 0) {
            printf("select task terminate!\n");
            break;
        }
        //判断server socket是否在描述符集合中
        if (FD_ISSET(sock, &fdRead)) {
            FD_CLR(sock, &fdRead);
            //等待客户端连接
            sockaddr_in clientAddr = {};
            int nAddrLen = sizeof(clientAddr);
            SOCKET clientSock = INVALID_SOCKET;

            clientSock = accept(sock, (sockaddr*)&clientAddr, &nAddrLen);
            if (INVALID_SOCKET == clientSock) {
                printf("ERROR: accept invalid client socket!\n");
            }
            else {
                printf("Accept new client, socket = %d, ip = %s, port = %d\n", clientSock, inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

                g_vecClients.push_back(clientSock);
            }
        }

        for (size_t n = 0; n < fdRead.fd_count; n++) {
            if (processor(fdRead.fd_array[n]) < 0) {
                auto iter = find(g_vecClients.begin(), g_vecClients.end(), (fdRead.fd_array[n]));
                if (g_vecClients.end() != iter) {
                    g_vecClients.erase(iter);
                }
            }
        }
    }

    //关闭socket
    for (size_t n = g_vecClients.size() - 1; n >= 0; n--) {
        closesocket(g_vecClients[n]);
    }
    closesocket(sock);

    WSACleanup();

    printf("Server exit, all tasks terminate!\n");

    getchar();

    return 0;
}



