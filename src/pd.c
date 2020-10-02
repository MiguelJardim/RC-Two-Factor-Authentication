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


int main(int argc, char **argv) {

    if (argc != 8) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* pd_ip = (char*) malloc(sizeof(char) * 16);
    strcpy(pd_ip, argv[1]);

    char* pd_port = (char*) malloc(sizeof(char) * 6);

    char* as_ip = (char*) malloc(sizeof(char) * 16);
    char* as_port = (char*) malloc(sizeof(char) * 6);

    char c;
    while ((c = getopt (argc, argv, "d:n:p:")) != -1) {
        switch (c) {
        case 'd':
            strcpy(pd_port, optarg);
            break;
        case 'n':
            strcpy(as_ip, optarg);
            break;
        case 'p':
            strcpy(as_port, optarg);
            break;
        case '?':
            if (optopt == 'c')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
            return 1;
        default:
            abort();
        }
    }

    char aux[9];
    int pos = 0;

    // read reg
    while ((c = getchar()) != ' ') {
        aux[pos++] = c;
    }
    aux[pos++] = '\0';
    char reg[4] = "reg";
    
    if (strcmp(aux, reg) != 0) {
        fprintf(stderr, "invalid input");
        exit(EXIT_FAILURE);
    }

    
    // read ist id
    char uid[6];
    pos = 0;

    c = getchar();
    if (c == '0') {
        fprintf(stderr, "invalid ist id");
        exit(EXIT_FAILURE);
    }
    else  {
        uid[pos++] = c;
    }

    int size = 1;
    while ((c = getchar()) != ' ') {
        uid[pos++] = c;
        size++;
    }
    if (size != 5) {
        fprintf(stderr, "invalid ist id");
        exit(EXIT_FAILURE);
    }
    uid[pos++] = '\0';

    // read password
    char password[9];
    pos = 0;

    size = 0;
    while ((c = getchar()) != '\n') {
        password[pos++] = c;
        size++;
    }
    if (size != 8) {
        fprintf(stderr, "invalid password");
        exit(EXIT_FAILURE);
    }
    password[pos++] = '\0';

    // REG UID pass PDIP PDport
    char message[45];

    if (sprintf(message, "REG %s %s %s %s\n", uid, password, pd_ip, pd_port) < 0) {
        fprintf(stderr, "ERRO");
        exit(EXIT_FAILURE);
    }

    printf("%s\n", message);

    int fd,errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[128];

    fd = socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd == -1) exit(1);

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP socket

    errcode = getaddrinfo(as_ip, as_port, &hints, &res) ;
    if(errcode!=0)  exit(1);

    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if(n==-1) exit(1);

    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, 128,0, (struct sockaddr*)&addr, &addrlen);
    if(n == -1) exit(1);

    write(1,"echo: ",6); write(1,buffer,n);

    freeaddrinfo(res);
    close (fd);

    /**

    char in_str[128];
    fd_set inputs, testfds;
    struct timeval timeout;
    int i,out_fds,n;

    FD_ZERO(&inputs); // Clear inputs
    FD_SET(0,&inputs); // Set standard input channel on

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
                if((n=read(0,in_str,127))!=0) {
                    if(n==-1) exit(1);

                    in_str[n]=0;
                    printf("From keyboard: %s\n",in_str);
                }
            }
        }
    }*/




    return 0;
}