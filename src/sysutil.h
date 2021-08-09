#ifndef __SYSUTIL_H__
#define __SYSUTIL_H__
#include "common.h"

int tcp_server(const char *host, unsigned short port);
int tcp_client();

char* statbuf_get_perms(struct stat *sbuf);
char* statbuf_get_date(struct stat *sbuf);

void send_fd(int sock_fd, int fd);
int  recv_fd(const int sock_fd);

unsigned long long get_time_sec();
unsigned long long get_time_usec();
void nano_sleep(double sleep_time);
#endif /*__SYSUTIL_H__*/