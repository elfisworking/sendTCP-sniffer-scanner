# sendTCP-sniffer-scanner
编写程序，根据 TCP 帧的结构，封装数据包发送到局域网中。  

捕获网络中的 TCP 数据包，解析数据包的内容，并将结果显示，并同时写入日志文件。    

发现服务器中开启的 TCP 服务，输出开启的 TCP 服务端口号

使用winpcap  

自定义了TCP首部数据结构  

自定义并填充数据包，发送数据包，捕获数据包   

可考虑采用多线程来加快扫描速度   

环境:

vs2017 

SDK 10.0.17763.0   修改SDK即可运行   

无需额外下包 所有包已经导入


运行演示：

![Image text](https://github.com/elfisworking/sendTCP-sniffer-scanner/blob/master/img/tcp.png)

![Image text](https://github.com/elfisworking/sendTCP-sniffer-scanner/blob/master/img/sniffer.png)

![Image text](https://github.com/elfisworking/sendTCP-sniffer-scanner/blob/master/img/scanner.png)

![Image text](https://github.com/elfisworking/sendTCP-sniffer-scanner/blob/master/img/TIM%E6%88%AA%E5%9B%BE20190511011053.png)
