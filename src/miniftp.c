#include "sysutil.h"
#include "session.h"
#include "tunable.h"
#include "parseconf.h"

//加载配置文件
void Test_Parseconf(){
	parseconf_load_file("miniftp.conf");
}

//全局会话结构指针
session_t* p_sess;

int main(int argc, char *argv[]){
	//加载配置文件
	parseconf_load_file("miniftp.conf");

	//判断是否为root用户启动
	if(getuid() != 0){
		printf("miniftp : must be started as root.\n");
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
			int    data_fd;
			int    pasv_listen_fd;
			int    data_process;
			//ftp协议状态
			char* rnfr_name;
			int is_ascii;
			long long restart_pos;

			//父子进程通道
			int parent_fd;
			int child_fd;
			//限速
			unsigned long long transfer_start_sec;
			unsigned long long transfer_start_usec;
		}session_t;
	*/

	//会话结构
	session_t sess = {
		//控制连接
		-1, -1, "", "", "",
		
		//数据连接
		NULL, -1, -1, 0,

		//ftp协议状态
		NULL,1,0,
		//父子进程通道
		-1, -1,
		//限速
		0,0
	};
	p_sess = &sess;

	int listenfd = tcp_server("192.168.81.3",  9000);

	int sockConn;
	struct sockaddr_in addrCli;
	socklen_t addrlen;
	while(1){
		sockConn = accept(listenfd, (struct sockaddr*)&addrCli, &addrlen);
		if(sockConn < 0){
			perror("accept");
			continue;
		}

		pid_t pid = fork();
		if(pid == -1)
			ERR_EXIT("fork");

		if(pid == 0){
			//Child Process
			close(listenfd);
			sess.ctrl_fd = sockConn;
			begin_session(&sess);
			exit(EXIT_SUCCESS);
		}
		else{
			//Parent Process
			close(sockConn);
		}
	}
	
	close(listenfd);
	return 0;
}

