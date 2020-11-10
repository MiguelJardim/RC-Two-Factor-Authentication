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
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <dirent.h>
#include <signal.h>

#include "../aux/validation.h"
#include "../aux/conection.h"
#include "../aux/constants.h"

int running = TRUE;

char* TID;
char* UID;
char* RID;

int validate_port(char* port) {
    if (strlen(port) != 5) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
}

int validate_password(char* password) {
    if (strlen(password) != 8) return -1;
    
    for (int i = 0; i < 8; i++) {
        if (!((password[i] >= '0' && password[i] <= '9') ||
            (password[i] >= 'a' && password[i] <= 'z') ||
            (password[i] >= 'A' && password[i] <= 'Z'))) return -1;
    }

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

int validate_uid(char* uid) {
    if (strlen(uid) != 5) return -1;
    else if (uid[0] == '0') return -1;

    for (int i = 1; i < 5; i++) {
        if (uid[i] < '0' || uid[i] > '9') return -1;
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


char* login_command(char* input) {

    int input_index = 0;    
    // read login
    char login[6] = "login\0";
    char* aux = split(input, &input_index, ' ', 6);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }
    if (strcmp(aux, login) != 0) {
        printf("login command expected\n");
        free(aux);
        return NULL;
    }
    // read ist id
    char* uid = split(input, &input_index, ' ', 6);
    if (uid == NULL) {
        printf("invalid uid\n");
        free(aux);
        free(uid);
        return NULL;
    }
    if (validate_uid(uid) == -1) {
        printf("invalid uid: %s\n", uid);
        free(aux);
        free(uid);
        return NULL;
    }
    // read password
    char* password = split(input, &input_index, '\n', 9);
    if (password == NULL) {
        printf("invalid password\n");
        free(aux);
        free(uid);
        free(password);
        return NULL;
    }
    if (validate_password(password) == -1) {
        printf("invalid password: %s\n", password);
        free(aux);
        free(uid);
        free(password);
        return NULL;
    }
    // LOG UID pass
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "LOG %s %s\n", uid, password) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(aux);
    free(uid);
    free(password);
    return message;
}

char* val_command(char* input, char* uid, char* rid) {

    int input_index = 0;
    // read val
    char val[4] = "val\0";
    char* aux = split(input, &input_index, ' ', 4);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }    
    if (strcmp(aux, val) != 0) {
        printf("val command expected\n");
        free(aux);
        return NULL;
    }
    // read VC
    char* vc = split(input, &input_index, ' ', 5);
    if (vc == NULL) {
        printf("invalid vc\n");
        free(aux);
        free(vc);
        return NULL;
    }
    // AUT UID RID VC
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "AUT %s %s %s\n",uid, rid, vc) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(aux);
    free(vc);
    return message;
}

char* list_command(char* input, char* uid, char* tid) {

    int input_index = 0;
    // read list or l
    char list[5] = "list\0", l[2] = "l\0";
    char* aux = split(input, &input_index, ' ', 5);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }    
    if ((strcmp(aux, list) != 0)||(strcmp(aux, l) != 0)) {
        printf("list or l command expected\n");
        free(aux);
        return NULL;
    }
    // LST UID TID
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "LST %s %s\n", uid, tid) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(aux);

    return message;
}

char* retrieve_command(char* input, char* uid, char* tid) {

    int input_index = 0;
    // read retrieve
    char retrieve[9] = "retrieve\0";
    char r[2] = "l\0";
    char* aux = split(input, &input_index, ' ', 9);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }
    if ((strcmp(aux, retrieve) != 0)||(strcmp(aux, r) != 0)) {
        printf("retrieve or r command expected\n");
        free(aux);
        return NULL;
    }
    char* filename = split(input, &input_index, ' ', 20);
    if (filename == NULL) {
        printf("invalid file name\n");
        free(aux);
        free(filename);
        return NULL;
    }
    // RTV UID TID Fname
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "RTV %s %s %s\n", uid, tid, filename) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(filename);
    free(aux);
    return message;
}

char* upload_command(char* input, char* uid, char* tid) {

    int input_index = 0;
    // read upload
    char upload[7] = "upload\0";
    char u[2] = "l\0";
    char* aux = split(input, &input_index, ' ', 7);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }    
    if ((strcmp(aux, upload) != 0)||(strcmp(aux, u) != 0)) {
        printf("upload or u command expected\n");
        free(aux);
        return NULL;
    }
    char* filename = split(input, &input_index, ' ', 20);
    if (filename == NULL) {
        printf("invalid file name\n");
        free(aux);
        free(filename);
        return NULL;
    }
    // UPL UID TID Fname Fsize data
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "UPL %s %s %s\n", uid, tid, filename) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(filename);
    free(aux);
    return message;
}

char* delete_command(char* input, char* uid, char* tid) {

    int input_index = 0;

    // read delete
    char delete[7] = "delete\0", d[2] = "l\0";
    char* aux = split(input, &input_index, ' ', 7);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }
    if ((strcmp(aux, delete) != 0)||(strcmp(aux, d) != 0)) {
        printf("upload or u command expected\n");
        free(aux);
        return NULL;
    }
    char* filename = split(input, &input_index, ' ', 20);
    if (filename == NULL) {
        printf("invalid filename\n");
        free(aux);
        free(filename);
        return NULL;
    }
    // DEL UID TID Fname
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "DEL %s %s %s\n", uid, tid, filename) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(filename);
    free(aux);
    return message;
}

char* req_command(char* input, char* uid, char* rid) {

    int input_index = 0;
    // read req
    char req[4] = "req\0";
    char L[2] = "L\0", R[2] = "R\0", U[2] = "U\0", D[2] = "D\0", X[2] = "X\0"; 
    char* aux = split(input, &input_index, ' ', 4);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }
    if ((strcmp(aux, req) != 0)) {
        printf("req command expected\n");
        free(aux);
        return NULL;
    }
    //(either L, R, U, D or X)
    char* fop = split(input, &input_index, ' ', 2);
    if (fop == NULL) {
        printf("invalid file operation\n");
        free(aux);
        free(fop);
        return NULL;
    }
    if ((strcmp(fop, L) != 0)||(strcmp(fop, R) != 0)||
        (strcmp(fop, U) != 0)||(strcmp(fop, D) != 0)||(strcmp(fop, X) != 0)) {
        printf("L, R, U, D or X expected\n");
        free(aux);
        free(fop);
        return NULL;
    }
    char* filename = split(input, &input_index, ' ', 20);
    if (filename == NULL) {
        printf("invalid filename\n");
        free(aux);
        free(fop);
        free(filename);
        return NULL;
    }
    // REQ UID RID Fop Fname
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "REQ %s %s %s %s\n", uid, rid, fop, filename) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(aux);
    free(fop);
    free(filename);
    return message;
}

char* remove_command(char* input, char* uid, char* tid) {

    int input_index = 0;
    // read remove
    char remove[7] = "remove\0";
    char x[2] = "x\0";

    char* aux = split(input, &input_index, ' ', 7);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }    
    if ((strcmp(aux, remove) != 0)||(strcmp(aux, x) != 0)) {
        printf("upload or u command expected\n");
        free(aux);
        return NULL;
    }
    // REM UID TID
    char* message = (char*) malloc(sizeof(char) * 45);

    if (sprintf(message, "DEL %s %s\n", uid, tid) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }
    free(aux);
    return message;
}

int main(int argc, char **argv) {
    // ./user[-n ASIP] [-p ASport] [-m FSIP] [-q FSport]

    if (argc < 1 || argc > 9) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    int as_ip_flag = FALSE,
        as_port_flag = FALSE,
        fs_ip_flag = FALSE,
        fs_port_flag = FALSE;

    char* as_ip = (char*) malloc(sizeof(char) * 16);
    char* as_port = (char*) malloc(sizeof(char) * 6);

    char* fs_ip = (char*) malloc(sizeof(char) * 16);
    char* fs_port = (char*) malloc(sizeof(char) * 6);

    char c;
    while ((c = getopt (argc, argv, "n:p:m:q:")) != -1) {
        switch (c) {
        case 'n':
            as_ip_flag = TRUE;
            strcpy(as_ip, optarg);
            break;
        case 'p':
            as_port_flag = TRUE;
            strcpy(as_port, optarg);
            break;
        case 'm':
            fs_ip_flag = TRUE;
            strcpy(fs_ip, optarg);
            break;
        case 'q':
            fs_port_flag = TRUE;
            strcpy(fs_port, optarg);
            break;
        default:
            abort();
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
    // default as_port value
    if (!as_port_flag) {
        if (sprintf(as_port, "58047") < 0 )  {
            // TODO erro
            exit(EXIT_FAILURE);
        }
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
    // default fs_port value
    if (!fs_port_flag) {
        if (sprintf(fs_port, "59047") < 0 )  {
            // TODO erro
            exit(EXIT_FAILURE);
        }
    }
    if (validate_port(fs_port) == -1) {
        printf("invalid fs_port: %s\n", fs_port);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    int fd_as = open_tcp(as_port);
    int fd_fs = open_tcp(fs_port);

    if (fd_as == -1) {
        printf("can't create socket\n");
        free(as_port);
        close(fd_as);
        exit(EXIT_FAILURE);
    }
    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        close(fd_fs);
        exit(EXIT_FAILURE);
    }
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    FD_ZERO(&inputs); 
    FD_SET(fd_as, &inputs);
    FD_SET(fd_fs, &inputs);
    while(running) {
        testfds = inputs;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        out_fds = select(FD_SETSIZE, &testfds, (fd_set *)NULL, (fd_set *)NULL, &timeout);
        switch(out_fds) {
            case 0:
                break;
            case -1:
                perror("select");
                exit(1);
            default:
        }  
    }
    
    return 0;
}
