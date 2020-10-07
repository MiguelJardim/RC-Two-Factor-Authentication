#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define FALSE 0
#define TRUE !(FALSE)

int validate_ip(char* ip) {
    if (strlen(ip) < 7 || strlen(ip) > 15) return -1;

    char* validated_ip = (char*) malloc(sizeof(char) * 16);
    int index = 0;
    int validated_index = 0;
    char c = ip[index++];
    int count = 0;
    int dot = 0;

    while (c != '\0') {
        count = 0;
        if (c < '0' || c > '9') {
            free(validated_ip);
            return -1;
        }
        else if (c != '0') validated_ip[validated_index++] = c;

        count ++;
        c = ip[index++];

        while (c != '.' && count < 3) {
            if (c < '0' || c > '9') {
                free(validated_ip);
                return -1;
            }
            else validated_ip[validated_index++] = c;
            c = ip[index++];
            count++;
        }
        if (dot < 3) {
            validated_ip[validated_index++] = '.';
            dot++;
        }
        c = ip[index++];

    }
    validated_ip[validated_index] = '\0';

    strcpy(ip, validated_ip);
    free(validated_ip);

    return 0;
}

int validate_port(char* port) {
    if (strlen(port) != 5) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
}

int open_tcp(char* fs_port, struct addrinfo **res) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints;

    fd = socket(AF_INET,SOCK_STREAM,0);
    if (fd == -1) exit(1); //error

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    errcode=getaddrinfo(NULL, fs_port, &hints, res);
    if((errcode)!= 0)/*error*/exit(1);

    n = bind(fd,(*res)->ai_addr,(*res)->ai_addrlen);
    if(n == -1) /*error*/ exit(1);

    if(listen(fd,5) == -1)/*error*/exit(1);

    return fd;

}

char* read_tcp(int fd, struct addrinfo **res) {
    char* buffer = (char*) malloc(sizeof(char) * 128);
    struct sockaddr_in addr;

    while(TRUE) {
        int newfd;

        socklen_t addrlen = sizeof(addr);
        if ((newfd = accept(fd,(struct sockaddr*)&addr, &addrlen)) == -1 )/*error*/ exit(1);

        ssize_t n = read (newfd,buffer,128);
        if(n == - 1)/*error*/exit(1);

        n = write(newfd,buffer,n);
        if(n == -1)/*error*/exit(1);

        close(newfd);
    }

    freeaddrinfo(*res);
    close (fd);

    return buffer;
}


int main() {

    char* as_ip = "193.136.138.142\0";
    char* as_port = "58011\0";

    char keyboard_message[100];

    struct addrinfo *res;
    int fd = open_tcp(as_port, &res);
    
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    FD_ZERO(&inputs); // Clear inputs
    FD_SET(0,&inputs); // Set standard input channel on
    FD_SET(fd,&inputs);

    while(1) {
        testfds=inputs;
        timeout.tv_sec=10;
        timeout.tv_usec=0;
        out_fds=select(FD_SETSIZE,&testfds,(fd_set *)NULL,(fd_set *)NULL,&timeout);
        switch(out_fds) {
            case 0:
                printf("Timeout event\n");
                break;
            case -1:
                perror("select");
                exit(1);
            default:
                if(FD_ISSET(0,&testfds)) {
                    if((n=read(0,keyboard_message,128))!=0) {
                        if(n==-1) exit(EXIT_FAILURE);
                        printf("From keyboard: %s\n",keyboard_message);
                    }
                }
                else if(FD_ISSET(fd,&testfds)) {
                    char* tcp_message = read_tcp(fd, &res);
                    if(tcp_message == NULL) {
                        // erro
                        exit(EXIT_FAILURE);
                    }
                    printf("From tcp: %s\n", tcp_message);
                }

        }
    }   

    return 0;
}