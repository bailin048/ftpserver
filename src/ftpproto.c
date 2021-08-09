#include "ftpproto.h"
#include "session.h"
#include "str.h"
#include "ftpcodes.h"
#include "sysutil.h"
#include "privsock.h"
#include "tunable.h"

extern session_t* p_sess;

void ftp_reply(session_t* sess, unsigned int code,const char *text){
    char buffer[MAX_BUFFER_SIZE] = {0};
    sprintf(buffer,"%d %s\r\n", code, text);
    send(sess->ctrl_fd, buffer,strlen(buffer), 0);
}

static void do_user(session_t* sess);
static void do_pass(session_t* sess);
static void do_syst(session_t* sess);
static void do_feat(session_t* sess);
static void do_pwd(session_t* sess);
static void do_type(session_t* sess);
static void do_port(session_t* sess);
static void do_pasv(session_t* sess);
static void do_list(session_t* sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t* sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_size(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_rest(session_t *sess);
static void do_quit(session_t *sess);

//命令映射
typedef struct ftpcmd{
    const char* cmd;
    void(*cmd_handler)(session_t* sess);
}ftpcmd_t;

ftpcmd_t ctrl_cmds[]={
    {"USER", do_user},	
    {"PASS", do_pass},
    {"SYST", do_syst},
    {"FEAT", do_feat},
    {"PWD" , do_pwd },
    {"TYPE", do_type},
    {"PORT", do_port},
    {"PASV", do_pasv},
    {"LIST", do_list},
	{"CWD" , do_cwd },
	{"CDUP", do_cdup},
	{"MKD" , do_mkd },
	{"RMD" , do_rmd },
	{"DELE", do_dele},
	{"SIZE", do_size},
	{"RNFR", do_rnfr},
	{"RNTO", do_rnto},
	{"RETR", do_retr},
	{"STOR", do_stor},
	{"REST", do_rest},
	{"QUIT", do_quit}
};

/////////////////////空闲断开////////////
//1.控制连接空闲断开/////////////////////
void handle_ctrl_timeout(int sig){
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_SUCCESS);
}

void start_cmdio_alarm(){
	if(tunable_idle_session_timeout > 0){
		signal(SIGALRM, handle_ctrl_timeout);//设置闹钟信号处理方式
		alarm(tunable_idle_session_timeout);//定闹钟
	}
}
//2.数据连接空闲断开/////////////////////
void start_data_alarm();
void handle_data_timeout(int sig){
	if(!p_sess->data_process){//空闲断开
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout, Reconnect Sorry.");
		exit(EXIT_FAILURE);
	}
	p_sess->data_process = 0;
	start_data_alarm();
}

void start_data_alarm(){
	if(tunable_data_connection_timeout > 0){
		signal(SIGALRM, handle_data_timeout);
		alarm(tunable_data_connection_timeout);
	}
}
/////////////////////end/////////////////

//ftp服务进程
void handle_child(session_t* sess){
    ftp_reply(sess, FTP_GREET,"(miniftp 1.0.0)");
    while(1){
        //循环等待客户端的命令并处理
        memset(sess->cmdline, 0 , MAX_COMMOND_LINE_SIZE);
        memset(sess->cmd, 0, MAX_CMD_SIZE);
        memset(sess->arg, 0, MAX_ARG_SIZE);
		//开启空闲断开
		start_cmdio_alarm();

        int ret = recv(sess->ctrl_fd, sess->cmdline, MAX_COMMOND_LINE_SIZE, 0);
        if(ret < 0)
            ERR_EXIT("recv");
        str_trim_crlf(sess->cmdline);
        str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
        //命令映射
        int table_size = sizeof(ctrl_cmds)/sizeof(ctrl_cmds[0]);
        int i;
        for(i = 0; i <table_size; ++i){
            if(strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0){
                if(ctrl_cmds[i].cmd_handler)
                    ctrl_cmds[i].cmd_handler(sess);
                else
                    ftp_reply(sess,FTP_COMMANDNOTIMPL,"Unimplement command.");
                break;
            }
        }
        if(i >= table_size)
            ftp_reply(sess, FTP_BADCMD, "Unknow command.");
    }
}

static void do_user(session_t* sess){
    struct passwd* pwd = getpwnam(sess->arg);
    if(pwd != NULL)
        sess->uid = pwd->pw_uid;//保存用户ID即uid
    ftp_reply(sess, FTP_GIVEPWORD, "Please sepcify the password");
}

static void do_pass(session_t* sess){
    //鉴权登录
    struct passwd* pwd = getpwuid(sess->uid);
    if(pwd == NULL){
        //用户不存在
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;
    }
    struct spwd* spd = getspnam(pwd->pw_name);
    if(NULL == spd){
        //用户不存在
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;
    }
    char *encrypted_pw = crypt(sess->arg, spd->sp_pwdp);
    if(strcmp(encrypted_pw, spd->sp_pwdp) != 0){
        //密码错误
        ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
        return;

    }

    //更改ftp服务进程
    setegid(pwd->pw_gid);
    seteuid(pwd->pw_uid);
    chdir(pwd->pw_dir);

    ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t* sess){
    ftp_reply(sess, FTP_SYSTOK, "Linux Type: L8");
}

static void do_feat(session_t* sess){
    send(sess->ctrl_fd, "211-Features:\r\n", strlen("211-Features:\r\n"), 0);
    send(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
    send(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
    send(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
    send(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
    send(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0);
    send(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"), 0);
    send(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"), 0);
    send(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"), 0);
    send(sess->ctrl_fd, "211 End\r\n", strlen("211 End\r\n"), 0);
}

static void do_pwd(session_t* sess){
    char cwd[MAX_CWD_SIZE] = {0};
    getcwd(cwd, MAX_CWD_SIZE);
    char text[MAX_BUFFER_SIZE] = {0};
    sprintf(text, "\"%s\"", cwd);
    ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_type(session_t* sess){
    if(strcmp(sess->arg,"A")==0 || strcmp(sess->arg,"a")==0){
        sess->is_ascii = 1;
        ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");

    }
    else if(strcmp(sess->arg,"I")==0 || strcmp(sess->arg,"i")==0){
        sess->is_ascii = 0;
        ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
    }
    else{
        //500 Unrecognised TYPE command.
        ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
    }
}

static void do_port(session_t* sess){
    //PORT XXX,XXX,XXXX,XXXX,XX,XX
    unsigned int v[6] = {0};
    sscanf(sess->arg,"%u,%u,%u,%u,%u,%u",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);

    sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr));
    //填充协议家族
    sess->port_addr->sin_family = AF_INET;
    //填充port
    unsigned char* p = (unsigned char*)&(sess->port_addr->sin_port); 
	p[0] = v[4];
	p[1] = v[5];
    //填充ip
    p = (unsigned char*)&(sess->port_addr->sin_addr);
    p[0] = v[0];
    p[1] = v[1];
    p[2] = v[2];
    p[3] = v[3];
    //响应主动模式
    ftp_reply(sess, FTP_PROTOK,"PORT command successful.Consider using PASV.");
}

static void do_pasv(session_t* sess){
    char ip[16] = "192.168.81.3";
    unsigned int v[4] = {0};
    sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1],&v[2],&v[3]);
    //0代表生成默认端口号
    int sockfd = tcp_server(ip,0);

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    if(getsockname(sockfd, (struct sockaddr*)&addr, &addrlen) < 0)
        ERR_EXIT("getsocknam");

    sess->pasv_listen_fd = sockfd;

    unsigned short port = ntohs(addr.sin_port);

    char text[MAX_BUFFER_SIZE] = {0};
    sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
            v[0],v[1],v[2],v[3], port>>8, port&0x00ff);

    //227 Entering Passive Mode (192,168,81,3,xxx,xxx).
    ftp_reply(sess, FTP_PASVOK, text);
}
/////////////////////////////////////////////////////
//数据连接
int port_active(session_t* sess){
    if(sess->port_addr != NULL)
        return 1;
    return 0;
}

int pasv_active(session_t* sess){
    if(sess->pasv_listen_fd != -1)
        return 1;
    return 0;
}
//确定传输模式及相应数据链路
static int get_transfer_fd(session_t* sess){
    if(!port_active(sess) && !pasv_active(sess)){
        //425 Use PORT or PASV first. 
        ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
        return -1;
    }

    if(port_active(sess)){
        int sock = tcp_client();
        socklen_t addrlen = sizeof(struct sockaddr);
        if(connect(sock, (struct sockaddr*)sess->port_addr, addrlen) < 0)
            return -1;
        //保存数据连接套接字
        sess->data_fd = sock;
    }
    if(pasv_active(sess)){
        int sockConn;
        struct sockaddr_in addr;
        socklen_t addrlen;
        if((sockConn = accept(sess->pasv_listen_fd, (struct sockaddr*)&addr, &addrlen)) < 0)
            return -1;
        sess->data_fd = sockConn;
    }

    if(sess->port_addr){
        free(sess->port_addr);
        sess->port_addr = NULL;
    }
    return 0;
}
//整理传输列表数据格式
void list_common(session_t* sess)
{
    DIR *dir = opendir(".");
    if(dir == NULL)
        ERR_EXIT("opendir");

    struct stat sbuf;
    char   buf[MAX_BUFFER_SIZE] = {0};
    unsigned int offset = 0;

    struct dirent *dt;
    while((dt = readdir(dir))){
        if(stat(dt->d_name,  &sbuf)<0)
            ERR_EXIT("stat");

        if(dt->d_name[0] == '.')
            continue;

        const char *perms = statbuf_get_perms(&sbuf);
        offset = sprintf(buf, "%s", perms);

        offset += sprintf(buf+offset, "%3d %-8d %-8d %8u ", 
                (int)sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, (unsigned int)sbuf.st_size);

        const char *pdate = statbuf_get_date(&sbuf);
        offset += sprintf(buf+offset, "%s ", pdate);

        sprintf(buf+offset, "%s\r\n", dt->d_name);
        //buf drwxrwxr-x    2 1000     1000          114 Dec 05  2020 93

        send(sess->data_fd, buf, strlen(buf), 0);
    }

    closedir(dir);
}
//传输文件列表
static void do_list(session_t* sess){
    //1 创建数据连接
    if(get_transfer_fd(sess) != 0)
        return;
    //2 150
    ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
    //3 传输列表
    list_common(sess);
    //4 226
    ftp_reply(sess,FTP_TRANSFEROK, "Directory send OK.");

    //关闭数据连接
    close(sess->data_fd);
    sess->data_fd = -1;
	//开启控制连接闹钟
	start_cmdio_alarm();
}
//切换文件夹——工作路径
static void do_cwd(session_t* sess){
	if(chdir(sess->arg) < 0)
		ftp_reply(sess,FTP_NOPERM, "Failed to change directory.");
	else
		ftp_reply(sess,FTP_CWDOK, "Directory successfully changed.");
}
//改变服务器上的父目录
static void do_cdup(session_t* sess){
	if(chdir("..") < 0){
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	} 
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}
//创建文件夹
static void do_mkd(session_t* sess){
	if(mkdir(sess->arg, 0775) < 0)
		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed.");
	else{
		char text[MAX_BUFFER_SIZE] = {0};
		sprintf(text, "\"%s\" created", sess->arg);
		ftp_reply(sess, FTP_MKDIROK, text);
	}
}
//删除文件夹
static void do_rmd(session_t* sess){
	if(rmdir(sess->arg) < 0)
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
	else
		ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}
//删除文件
static void do_dele(session_t* sess){
	if(unlink(sess->arg) < 0)
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
	else
		ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}
//获取文件大小
static void do_size(session_t* sess){
	struct stat sbuf;
	if(stat(sess->arg, &sbuf) < 0)
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
	else{
		char text[MAX_BUFFER_SIZE] = {0};
		sprintf(text, "%d", (int)sbuf.st_size);
		ftp_reply(sess, FTP_SIZEOK, text);
	}
}
//对旧路径重命名
static void do_rnfr(session_t* sess){
	unsigned int len = strlen(sess->arg);
	sess->rnfr_name = (char*)malloc(len + 1);
	memset(sess->rnfr_name, 0, len + 1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
//对新路径重命名
static void do_rnto(session_t* sess){
	if(sess->rnfr_name == NULL){
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	if(rename(sess->rnfr_name, sess->arg) < 0)
		ftp_reply(sess, FTP_NOPERM, "Rename failed.");
	else{
		free(sess->rnfr_name);
		sess->rnfr_name = NULL;
		ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
	}
}
///////////////////////限速模块/////
void limit_rate(session_t *sess, unsigned long bytes_transfer, int is_upload){
	unsigned long long cur_sec = get_time_sec();
	unsigned long long cur_usec = get_time_usec();

	double pass_time = (double)(cur_sec - sess->transfer_start_sec);
	pass_time += ((double)(cur_usec - sess->transfer_start_usec) / 1000000);
	//当前传输速度
	unsigned long cur_rate = (unsigned long)(bytes_transfer / pass_time);
	double rate_ratio; //速率
	if(is_upload){//上传限速
		if(tunable_upload_max_rate==0 || cur_rate<=tunable_upload_max_rate){
			//不限速
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = cur_rate / tunable_upload_max_rate;
	}
	else{//下载限速
		//下载
		if(tunable_download_max_rate==0 || cur_rate <= tunable_download_max_rate){
			//不限速
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = cur_rate / tunable_download_max_rate;
	}
	double sleep_time = (rate_ratio - 1)*pass_time;
	//休眠
	nano_sleep(sleep_time);
	//重新登记开始时间
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
}
////////////////////////////////////
//下载文件
static void do_retr(session_t* sess){
	//建立数据传输链路
	if(get_transfer_fd(sess) != 0)
		return;
	int fd;
	if((fd = open(sess->arg, O_RDONLY)) < 0){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//响应传输模式
	struct stat sbuf;
	fstat(fd, &sbuf);
	char buf[MAX_BUFFER_SIZE] = {0};
	if(sess->is_ascii)
		sprintf(buf, "Opening ASCII mode data connection for %s (%lld bytes).", sess->arg, (unsigned long long)sbuf.st_size);
	else
		sprintf(buf, "Opening BINARY mode data connection for %s (%lld bytes).", sess->arg, (unsigned long long)sbuf.st_size);
	ftp_reply(sess, FTP_DATACONN, buf);
	//传输数据
	unsigned long long total_size = sbuf.st_size;
	//断点续载
	unsigned long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if(offset >= total_size)
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	else{
		if(lseek(fd, offset, SEEK_SET) < 0)
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		else{
			int read_count = 0;
			total_size -= offset;
			//登记时间
			sess->transfer_start_sec = get_time_sec();
			sess->transfer_start_usec = get_time_usec();
			while(1){
				memset(buf, 0, MAX_BUFFER_SIZE);
				read_count = total_size > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE:total_size;
				int ret = read(fd, buf, read_count);
				//读取出错
				if(ret == -1 || ret != read_count){
					ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
					break;
				}
				//文件读取结束
				if(ret == 0){
					ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
					break;
				}
				//处于数据连接状态
				sess->data_process = 1;
				//限速 —— 登记结束时间
				limit_rate(sess, ret, 0);
				//发送数据
				send(sess->data_fd, buf, ret, 0);
				total_size -= read_count;
			}
		}
	}
	close(fd);
	if(sess->data_fd != -1){
		close(sess->data_fd);
		sess->data_fd = -1;
	}
	//数据传完，控制连接闹钟启用
	start_cmdio_alarm();
}
//上传文件
static void do_stor(session_t *sess){
	if(get_transfer_fd(sess) != 0)
		return;

	int fd;
	if((fd = open(sess->arg, O_CREAT|O_WRONLY, 0755)) < 0){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//回复150
	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");

	//断点续传
	unsigned long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if(lseek(fd, offset, SEEK_SET) < 0){
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}
	//登记时间
	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
	//传输数据
	char buf[MAX_BUFFER_SIZE] = {0};
	while(1){
		memset(buf, 0, MAX_BUFFER_SIZE);
		int ret = recv(sess->data_fd, buf, MAX_BUFFER_SIZE, 0);
		if(ret == -1){
			ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
			break;
		}
		if(ret == 0){
			ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
			break;
		}
		//处于数据连接状态
		sess->data_process = 1;
		//限速
		limit_rate(sess, ret, 1);
		write(fd, buf, ret);
	}

	close(fd);
	if(sess->data_fd != -1){
		close(sess->data_fd);
		sess->data_fd = -1;
	}
	//开启控制连接闹钟
	start_cmdio_alarm();
}

//断点续传或续载
static void do_rest(session_t *sess){
	sess->restart_pos = (unsigned long long)atoll(sess->arg);
	char text[MAX_BUFFER_SIZE] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}
 
static void do_quit(session_t* sess){
	ftp_reply(sess, FTP_GOODBYE, "Goodbye");
	if(sess->data_fd != -1)//关闭数据连接	
		close(sess->data_fd);
	exit(EXIT_SUCCESS);
}
