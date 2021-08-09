#ifndef __SESSION_H__
#define __SESSION_H__

#include "common.h"
typedef struct session{
	//控制连接
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMOND_LINE_SIZE];
	char cmd[MAX_CMD_SIZE];
	char arg[MAX_ARG_SIZE];
	//数据连接
	struct sockaddr_in *port_addr;
	int    data_fd;
	int    pasv_listen_fd;
	int    data_process;  //用于判断是否处于数据连接状态
	//ftp协议状态
	char *rnfr_name;
	int is_ascii;
	unsigned long long restart_pos;
	unsigned int  max_clients;
	unsigned int  max_per_ip;
	//父子进程通道
	int parent_fd;
	int child_fd;
	//限速
	unsigned long long transfer_start_sec;
	unsigned long long transfer_start_usec;
}session_t;

void begin_session(session_t* sess);
#endif/*__SESSION_H__*/