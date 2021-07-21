#include "sysutil.h"

int tcp_server(const char* host,unsigned short port){
    int listenfd;
    //创建套接字
    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        ERR_EXIT("socket failed!");

    struct sockaddr_in addrSer;
    addrSer.sin_family = AF_INET;
    addrSer.sin_port = htons(port);
    addrSer.sin_addr.s_addr = inet_addr(host);
    //设置地址重用
    int on = 1;
    if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
        ERR_EXIT("setsockopt failed!");
    //绑定
    if(bind(listenfd, (struct sockaddr*)&addrSer, sizeof(addrSer)) < 0)
        ERR_EXIT("bind failed!");
    //监听
    if(listen(listenfd, SOMAXCONN) < 0)
        ERR_EXIT("listen failed!");
    return listenfd;
}
