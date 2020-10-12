#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aux/validation.h"
#include "../aux/conection.h"

#define FALSE 0
#define TRUE !(FALSE)

char* read_reg_instruction(char* pd_ip, char* pd_port, char* input) {

    int input_index = 0;

    // read reg
    char reg[4] = "reg\0";

    char* aux = split(input, &input_index, ' ', 4);
    if (aux == NULL) exit(EXIT_FAILURE);
    
    if (strcmp(aux, reg) != 0) {
        fprintf(stderr, "invalid input\n");
        exit(EXIT_FAILURE);
    }

    // read ist id

    char* uid = split(input, &input_index, ' ', 6);
    if (uid == NULL) exit(EXIT_FAILURE);

    if (validate_uid(uid) == -1) {
        printf("invalid uid: %s\n", uid);
        return NULL;
    }

    // read password
    char* password = split(input, &input_index, '\n', 9);
    if (password == NULL) exit(EXIT_FAILURE);

    if (validate_password(password) == -1) {
        printf("invalid password: %s\n", password);
        return NULL;
    }

    // REG UID pass PDIP PDport
    char* message = (char*) malloc(sizeof(char) * 45);

    if (sprintf(message, "REG %s %s %s %s\n", uid, password, pd_ip, pd_port) < 0) {
        fprintf(stderr, "ERRO");
        exit(EXIT_FAILURE);
    }

    free(aux);
    free(uid);
    free(password);

    return message;
}

int main(int argc, char **argv) {

    if (argc < 2 || argc > 8) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    int as_ip_flag = FALSE, pd_port_flag = FALSE, as_port_flag = FALSE;

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
            pd_port_flag = TRUE;
            break;
        case 'n':
            strcpy(as_ip, optarg);
            as_ip_flag = TRUE;
            break;
        case 'p':
            strcpy(as_port, optarg);
            as_port_flag = TRUE;
            break;
        default:
            abort();
        }
    }
    
    if (!as_ip_flag) strcpy(as_ip, pd_ip);
    if (!pd_port_flag) {
        if (sprintf(pd_port, "57047") < 0) {
            fprintf(stderr, "ERRO");
            exit(EXIT_FAILURE);
        }
    }
    if (!as_port_flag) {
        if (sprintf(as_port, "58047") < 0) {
            fprintf(stderr, "ERRO");
            exit(EXIT_FAILURE);
        }
    }

    if (validate_ip(pd_ip) == -1) {
        printf("invalid pd_ip: %s\n", pd_ip);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }
    if (as_ip_flag && validate_ip(as_ip) == -1) {
        printf("invalid as_ip: %s\n", as_ip);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }
    if (pd_port_flag && validate_port(pd_port) == -1) {
        printf("invalid pd_port: %s\n", pd_port);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }
    if (as_port_flag && validate_port(as_port) == -1) {
        printf("invalid as_port: %s\n", as_port);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }

    int fd_as = open_udp(as_port);

    char* in_str = (char*) malloc(sizeof(char) * 127);
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    FD_ZERO(&inputs); 
    FD_SET(0,&inputs);
    FD_SET(fd_as, &inputs);

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
                        char exit_txt[5] = "exit\0";
                        if (strcmp(in_str, exit_txt) == 0) {
                            // free
                            exit(EXIT_SUCCESS);
                        }
                        
                        char* message = read_reg_instruction(in_str, pd_ip, pd_port);
                        if (message == NULL) {
                            free(pd_ip);
                            free(pd_port);
                            free(as_ip);
                            free(as_port);
                            exit(EXIT_FAILURE);
                        }

                        char* answer = send_udp(message, as_ip, as_port);

                        char expected_message[8] = "RRG OK\n\0";

                        if (strcmp(expected_message, answer) == 0) {
                            printf("Registration successfull\n");
                        }
                        else {
                            printf("%s", answer);
                        }
                        // TODO handle invalid answer

                    }
                }
                else if (FD_ISSET(fd_as, &testfds)) {
                    struct sockaddr_in addr;
                    socklen_t addrlen=sizeof(addr);
                    n= recvfrom (fd_as,in_str,128,0, (struct sockaddr*)&addr,&addrlen);
                    if(n==-1)/*error*/exit(1);
                    
                }
        }
    }
    return 0;
}