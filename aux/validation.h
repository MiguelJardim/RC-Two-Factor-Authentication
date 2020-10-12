#ifndef VALIDATION_H_
#define VALIDATION_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

char* split(char* input, int* index, char separator, int size);
int validate_uid(char* uid);
int validate_password(char* password);
int validate_ip(char* ip);
int validate_port(char* port);

#endif