#ifndef CONECTION_H_
#define CONECTION_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

char* send_udp(char* message, char* ip, char* port);
int open_udp(char* port);
int open_tcp(char* port);

#endif