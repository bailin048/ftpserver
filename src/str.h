#ifndef __STR_H__
#define __STR_H__

#include "common.h"

void str_trim_crlf(char* str);
void str_split(const char* str,char* left,char* right, char token);

#endif /*__STR_H__*/ 