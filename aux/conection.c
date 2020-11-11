#include "conection.h"

#include "../aux/constants.h"

char* send_udp(char* message, char* ip, char* port) {
    int fd,errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);

    fd = socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd == -1) return NULL;

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP socket

    errcode = getaddrinfo(ip, port, &hints, &res) ;
    if(errcode!=0)  return NULL;

    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if(n==-1) return NULL;

    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, BUFFER_SIZE,0, (struct sockaddr*)&addr, &addrlen);
    if(n == -1) return NULL;

    freeaddrinfo(res);
    close (fd);

    return buffer;
}

int open_udp(char* port) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints,*res;
    
    fd=socket(AF_INET,SOCK_DGRAM,0);
    if(fd==-1) return -1;

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; // IPv4
    hints.ai_socktype=SOCK_DGRAM; // UDP socket
    hints.ai_flags=AI_PASSIVE;

    errcode= getaddrinfo(NULL,port,&hints,&res);
    if(errcode!=0) return -1;

    n= bind (fd,res->ai_addr, res->ai_addrlen);
    if(n==-1) return -1;

    freeaddrinfo(res);
    
    return fd;

}

int open_tcp(char* port) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints,*res;

    fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd==-1) {
        freeaddrinfo(res);
        return -1;
    }

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_flags=AI_PASSIVE;

    errcode=getaddrinfo(NULL,port,&hints,&res);
    if((errcode)!=0) {
        freeaddrinfo(res);
        return -1;
    }

    n=bind(fd,res->ai_addr,res->ai_addrlen);
    freeaddrinfo(res);
    if(n==-1) return -1;

    if(listen(fd,MAX_USERS)==-1) return -1;

    return fd;
}