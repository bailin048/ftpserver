#ifndef __SESSION_H__
#define __SESSION_H__

#include "common.h"
typedef struct session{
	//��������
	uid_t uid;
    int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE_SIZE];
	char cmd[MAX_CMD_SIZE];
	char arg[MAX_ARG_SIZE];
	//��������
	struct sockaddr_in* port_addr;
	int data_fd;
	int pasv_listen_fd;
	//ftpЭ��״̬
	int is_ascii;
	//���ӽ���ͬͨ��
	int parent_fd;
	int child_fd;
}session_t;

void begin_session(session_t* sess);
#endif/*__SESSION_H__*/