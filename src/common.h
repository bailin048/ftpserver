#ifndef __COMMON_H__
#define __COMMON_H__

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pwd.h>
#include <shadow.h>
#include <crypt.h>

#define ERR_EXIT(msg)\
    do{\
        perror(msg);\
        exit(EXIT_FAILURE);\
    }while(0)

#define MAX_COMMAND_LINE_SIZE 1024
#define MAX_CMD_SIZE          128
#define MAX_ARG_SIZE          1024

#define MAX_BUFFER_SIZE       1024
#define MAX_CWD_SIZE          512

#endif/*__COMMON_H__*/
