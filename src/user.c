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
#define SIZE 30


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

int connect_tcp(char* ip, char* port) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints, *res;

    fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd==-1) exit(1); //error

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET;
    hints.ai_socktype=SOCK_STREAM;
    errcode= getaddrinfo(ip, port, &hints,&res);
    if(errcode!=0)/*error*/exit(1);

    n= connect (fd,res->ai_addr,res->ai_addrlen);
    if(n==-1)/*error*/exit(1);

    freeaddrinfo(res); 

    return fd;

}

int write_tcp(int fd, char* buffer) {
    int n = write (fd, buffer, strlen(buffer));

    return n;
}

char* read_tcp(int fd) {
    char* buffer = (char*) malloc(sizeof(char) * 128);
    
    int n= read (fd,buffer,128);
    if(n==-1)/*error*/exit(1);

    return buffer;
}


int main(int argc, char **argv) {
    // ./user[-n ASIP] [-p ASport] [-m FSIP] [-q FSport]

    if (argc < 1 || argc > 9) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    int as_ip_f = FALSE, as_port_f = FALSE, fs_ip_f = FALSE, fs_port_f = FALSE;

    char* as_ip = (char*) malloc(sizeof(char) * 16);
    char* as_port = (char*) malloc(sizeof(char) * 6);

    char* fs_ip = (char*) malloc(sizeof(char) * 16);
    char* fs_port = (char*) malloc(sizeof(char) * 6);

    char c;
    while ((c = getopt (argc, argv, "n:p:m:q:")) != -1) {
        switch (c) {
        case 'n':
            as_ip_f = TRUE;
            strcpy(as_ip, optarg);
            break;
        case 'p':
            as_port_f = TRUE;
            strcpy(as_port, optarg);
            break;
        case 'm':
            fs_ip_f = TRUE;
            strcpy(fs_ip, optarg);
            break;
        case 'q':
            fs_port_f = TRUE;
            strcpy(fs_port, optarg);
            break;
        default:
            abort();
        }
    }

    // ip omitido fica o da propria maquina, quer as, quer fs

    // default as_port value
    if (!as_port_f) {
        if (sprintf(as_port, "58047") < 0 )  {
            // TODO erro
            exit(EXIT_FAILURE);
        }
    }
    if (!fs_port_f) {
        if (sprintf(fs_port, "59047") < 0 )  {
            // TODO erro
            exit(EXIT_FAILURE);
        }
    }

    if (validate_ip(as_ip) == -1) {
        printf("invalid as_ip: %s\n", as_ip);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }
    if (validate_port(as_port) == -1) {
        printf("invalid as_port: %s\n", as_port);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }
    if (validate_ip(fs_ip) == -1) {
        printf("invalid fs_ip: %s\n", fs_ip);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }
    if (validate_port(fs_port) == -1) {
        printf("invalid fs_port: %s\n", fs_port);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    

    // printf("%s %s %s %s\n", as_ip, as_port, fs_ip, fs_port);

    char buffer[128] = "LOG 92528 password\n\0";
    char* output;

    int fd = connect_tcp(as_ip, as_port);




    int n = write_tcp(fd, buffer);
    if (n == -1 ) exit(EXIT_FAILURE); // error
    output = read_tcp(fd);
     
    close(fd);

    printf("%s\n", output);
    
    return 0;
}