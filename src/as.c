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
#define TRUE 1

int validate_port(char* port) {
    if (strlen(port) != 5) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
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

char* read_message(char* message, char* ip, char* port) {
    int input_index = 0;

    char* action = split(message, &input_index, ' ', 4);
    char aux[4] = "REG\0";
    char ok[8] = "RRG OK\0";
    char nok[8] = "RRG NOK\0";
    char* reg_status = (char*) malloc(sizeof(char) * 8);

    if (strcmp(aux, action) != 0) {
        free(action);
        strcpy(reg_status, nok);
        return reg_status;
    }

    char* uid = split(message, &input_index, ' ', 6);
    if (validate_uid(uid) != 0) {
        free(action);
        free(uid);
        strcpy(reg_status, nok);
        return reg_status;
    }

    char* password = split(message, &input_index, ' ', 9);
    if (validate_password(password) != 0) {
        free(action);
        free(uid);
        free(password);
        strcpy(reg_status, nok);
        return reg_status;
    }

    char* pd_ip = split(message, &input_index, ' ', 16);
    strcpy(ip, pd_ip);
    if (validate_ip(pd_ip) != 0) {
        free(action);
        free(uid);
        free(password);
        free(pd_ip);
        strcpy(reg_status, nok);
        return reg_status;
    }


    char* pd_port = split(message, &input_index, ' ', 6);
    strcpy(port, pd_port);
    if (validate_port(pd_port) != 0) {
        free(action);
        free(uid);
        free(password);
        free(pd_ip);
        free(pd_port);
        strcpy(reg_status, nok);
        return reg_status;
    }

    strcpy(reg_status, ok);
    return reg_status;
}

char* receive_message(char* as_port) {
    int fd, errcode;
    struct addrinfo hints, *res;
    ssize_t n;
    socklen_t addrlen;
    struct sockaddr_in addr;


    fd = socket(AF_INET,SOCK_DGRAM, 0);
    if (fd == -1) /*error*/exit(1);

    memset (&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo (NULL, as_port, &hints, &res);
    if (errcode != 0) /*error*/ exit(1);

    n = bind (fd, res->ai_addr, res->ai_addrlen);
    if (n ==-1) /*error*/ exit(1);

    char* buffer = (char*) malloc(sizeof(char) * 128);
    
    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, 128, 0, (struct sockaddr*)&addr, &addrlen);
    if (n == -1) /*error*/exit(1);

    freeaddrinfo(res);
    close (fd);

    return buffer;
}

void send_message(char* message, char* pd_ip, char* pd_port) {
    int fd, errcode;
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

    errcode = getaddrinfo(pd_ip, pd_port, &hints, &res);
    if(errcode!=0)  exit(1);

    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if(n==-1) exit(1);

    freeaddrinfo(res);
    close (fd);
}


int main(int argc, char **argv) {

    if (argc < 1 || argc > 4) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* as_port = (char*) malloc(sizeof(char) * 6);

    int flagV;
    int flagPort = FALSE;

    char c;
    while ((c = getopt (argc, argv, "p:v")) != -1) {
        switch (c) {
        case 'p':
            strcpy(as_port, optarg);
            flagPort = TRUE;
            break;
        case 'v':
            flagV = TRUE;
            break;
        default:
            abort();
        }
    }

    
    if (flagPort == FALSE) {
        char default_port[6] = "58047\0";
        strcpy(as_port, default_port);
    }

    if (validate_port(as_port) == -1) {
        printf("invalid as_port\n");
        free(as_port);
        exit(EXIT_FAILURE);
    }

    char* message_received = receive_message(as_port);
    printf("%s", message_received);
    char* pd_ip = (char*) malloc(sizeof(char) * 16);
    char* pd_port = (char*) malloc(sizeof(char) * 6);
    char* reg_status = read_message(message_received, pd_ip, pd_port);
    send_message(reg_status, pd_ip, pd_port);






}