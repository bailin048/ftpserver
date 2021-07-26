#ifndef __SESSION_H__
#define __SESSION_H__

#include "common.h"
typedef struct session{
	//控制连接
	uid_t uid;
    int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE_SIZE];
	char cmd[MAX_CMD_SIZE];
	char arg[MAX_ARG_SIZE];
	//数据连接
	struct sockaddr_in* port_addr;
	int data_fd;
	int pasv_listen_fd;
	//ftp协议状态
	int is_ascii;
	//父子进程同通道
	int parent_fd;
	int child_fd;
}session_t;

void begin_session(session_t* sess);
#endif/*__SESSION_H__*/