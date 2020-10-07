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

#define AS_PORT "58011"
#define AS_IP "193.136.138.142"

char* split(char* input, int* index, char separator, int size) {
    char* output = (char*) malloc(sizeof(char) * size);
    int output_index = 0;

    char c = input[(*index)++];
    if (c == separator) {
        free(output);
        return NULL;
    }

    while (c != separator && c != EOF) {
        if (output_index == size - 1) {
            free(output);
            return NULL;
        }
        output[output_index++] = c;
        c = input[(*index)++];
    }

    output[output_index] = '\0';

    return output;
}

int validate_port(char* port) {
    if (strlen(port) != 5) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
}

char* send_udp(char* message, char* dest_ip, char* dest_port) {
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

    errcode = getaddrinfo(dest_ip, dest_port, &hints, &res) ;
    if(errcode!=0)  exit(1);

    n = sendto(fd, message, strlen(message) + 1, 0, res->ai_addr, res->ai_addrlen);
    if(n==-1) exit(1);

    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, 128,0, (struct sockaddr*)&addr, &addrlen);
    if(n == -1) exit(1);

    freeaddrinfo(res);
    close (fd);

    return buffer;
}

char tcp(char* fs_port) {
    int fd,errcode, newfd;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[128];

    fd = socket(AF_INET,SOCK_STREAM,0);
    if (fd == -1) exit(1); //error

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    errcode=getaddrinfo(NULL, fs_port, &hints, &res);
    if((errcode)!= 0)/*error*/exit(1);

    n = bind(fd,res->ai_addr,res->ai_addrlen);
    if(n == -1) /*error*/ exit(1);

    if(listen(fd,5) == -1)/*error*/exit(1);

    while(1) {
        addrlen=sizeof(addr);
        if ((newfd=accept(fd,(struct sockaddr*)&addr, &addrlen)) == -1 )/*error*/ exit(1);

        n = read (newfd,buffer,128);
        if(n == - 1)/*error*/exit(1);

        write(1,"received: ",10);write(1,buffer,n);

        n = write(newfd,buffer,n);
        if(n == -1)/*error*/exit(1);

        close(newfd);
    }

    freeaddrinfo(res);
    close (fd);


    return 0;
}


int main(int argc, char **argv) {

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* fs_port = (char*) malloc(sizeof(char) * 6);
    int verbose;

    int c;
    while ((c = getopt (argc, argv, "p:v")) != -1) {
        switch (c) {
        case 'p':
            strcpy(fs_port, optarg);
            break;
        case 'v':
            verbose = TRUE;
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }

    if (validate_port(fs_port) == -1) {
        printf("invalid fs_port: %s\n", fs_port);
        free(fs_port);
        exit(EXIT_FAILURE);
    }


    return 0;
}