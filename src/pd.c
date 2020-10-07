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

int validate_uid(char* uid) {
    if (strlen(uid) != 5) return -1;
    else if (uid[0] == '0') return -1;

    for (int i = 1; i < 5; i++) {
        if (uid[i] < '0' || uid[i] > '9') return -1;
    }

    return 0;
}

int validate_password(char* password) {
    if (strlen(password) != 8) return -1;
    
    for (int i = 0; i < 8; i++) {
        if (!((password[i] >= '0' && password[i] <= '9') || (password[i] >= 'a' && password[i] <= 'z') || (password[i] >= 'A' && password[i] <= 'Z'))) return -1;
    }

    return 0;
}

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

char* read_input(char* pd_ip, char* pd_port) {
    char input[256];

    if (fgets(input, 256, stdin) == NULL) {
        exit(EXIT_FAILURE);
    }

    char exit_txt[5] = "exit\0";
    if (strcmp(input, exit_txt) == 0) {
        exit(EXIT_SUCCESS);
    }

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

char* send_message(char* message, char* as_ip, char* as_port) {
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

    errcode = getaddrinfo(as_ip, as_port, &hints, &res) ;
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


int main(int argc, char **argv) {

    if (argc < 2 || argc > 8) {
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
        default:
            abort();
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
    if (validate_ip(as_ip) == -1) {
        printf("invalid as_ip: %s\n", as_ip);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }
    if (validate_port(pd_port) == -1) {
        printf("invalid pd_port: %s\n", pd_port);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }
    if (validate_port(as_port) == -1) {
        printf("invalid as_port: %s\n", as_port);
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }

    char* message = read_input(pd_ip, pd_port);
    if (message == NULL) {
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }

    char* answer = send_message(message, as_ip, as_port);

    char expected_message[8] = "RRG OK\n\0";

    if (strcmp(expected_message, answer) == 0) {
        printf("Registration successfull\n");
    }
    else {
        printf("%s", answer);
    }
    // TODO handle invalid answer


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