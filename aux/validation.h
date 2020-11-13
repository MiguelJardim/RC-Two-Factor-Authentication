#ifndef VALIDATION_H_
#define VALIDATION_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

char* split(char* input, int* index, char separator, int size);
int validate_uid(char* uid);
int validate_tid(char* tid);
int validate_password(char* password);
int validate_ip(char* ip);
int validate_port(char* port);
int validate_rid(char* rid);
int validate_vc(char* vc);
int validate_fop(char* fop);
int validate_filename(char* fname);
int is_number(char* number);

#endif
