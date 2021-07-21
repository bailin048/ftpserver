#include "sysutil.h"
#include "session.h"

int main(int argc,char* argv[]){
    //判断是否是root用户启动的ftp服务端
    if(getuid() != 0){
        printf("miniftp: must be start as root.\n");
        exit(EXIT_FAILURE);
    }
	/*
		typedef struct session
		{
			//控制连接
			uid_t uid;
			int ctrl_fd;
			char cmdline[MAX_COMMOND_LINE_SIZE];
			char cmd[MAX_CMD_SIZE];
			char arg[MAX_ARG_SIZE];

			//数据连接
			struct sockaddr_in *port_addr;

			//ftp协议状态
			int is_ascii;
		}session_t;
	*/
    //会话结构
    session_t sess = {
		//控制连接
		-1,-1,"","","",
		//数据连接
		NULL,
		//ftp协议状态
		1
	};
    int listenfd = tcp_server("172.17.0.4", 9000);

    int sockConn;
    struct sockaddr_in addrCli;
    socklen_t addrlen;
    while(1){
        sockConn = accept(listenfd, (struct sockaddr*)&addrCli, &addrlen);
        if(sockConn < 0){
            perror("accept failed!");
            continue;
        }
        pid_t pid = fork();
        if(-1 == pid)
            ERR_EXIT("fork failed!");
        if(pid == 0){
            //子进程处理
            close(listenfd);
            sess.ctrl_fd = sockConn;
            begin_session(&sess);
            exit(EXIT_FAILURE);
        }
        else{
            //父进程处理
            close(sockConn);
        }
    }
    close(listenfd);
    return 0; 
}

