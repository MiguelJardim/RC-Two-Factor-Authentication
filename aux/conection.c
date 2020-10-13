#include "conection.h"

char* send_udp(char* message, char* ip, char* port) {
    int fd,errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char* buffer = (char*) malloc(sizeof(char) * 128);

    fd = socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd == -1) exit(1);

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP socket

    errcode = getaddrinfo(ip, port, &hints, &res) ;
    if(errcode!=0)  exit(1);

    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if(n==-1) exit(1);

    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, 128,0, (struct sockaddr*)&addr, &addrlen);
    if(n == -1) exit(1);

    freeaddrinfo(res);
    close (fd);

    return buffer;
}

int open_udp(char* port) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints,*res;
    
    fd=socket(AF_INET,SOCK_DGRAM,0);
    if(fd==-1) /*error*/exit(1);

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; // IPv4
    hints.ai_socktype=SOCK_DGRAM; // UDP socket
    hints.ai_flags=AI_PASSIVE;
    printf("-%s-", port);

    errcode= getaddrinfo (NULL,port,&hints,&res);
    if(errcode!=0) /*error*/ exit(1);

    n= bind (fd,res->ai_addr, res->ai_addrlen);
    if(n==-1) /*error*/ exit(1);

    //freeaddrinfo(res);
    
    return fd;

}