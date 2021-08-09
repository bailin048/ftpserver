#ifndef __FTPPROTO_H__
#define __FTPPROTO_H__

#include "common.h"
#include "session.h"

void handle_child(session_t* sess);
void ftp_reply(session_t *sess, unsigned int code, const char *text);

#endif /*__FTPPROTO_H__*/