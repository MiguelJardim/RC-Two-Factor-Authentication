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

#include "../aux/validation.h"
#include "../aux/conection.h"
#include "../aux/constants.h"

int list(int fd, char* request_message) {
    int index = 4;
    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    char* tid = split(request_message, &index, '\n', TID_SIZE + 1);
    if (!uid || !tid) return -1;

    char* message = (char*) malloc(sizeof(char) * (4 + UID_SIZE + 1 + TID_SIZE + 1));
    sprintf(message, "VLD %s %s\n", uid, tid);
    
    char* answer = send_udp(message, AS_IP, AS_PORT);
    printf("answer: %s\n", answer);

    printf("list, uid:%s, tid:%s.\n", uid, tid);
    return 0;

}

int retrieve(int fd, char* request_message) {
    int index = 4;
    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    char* tid = split(request_message, &index, ' ', TID_SIZE + 1);
    char* fname = split(request_message, &index, '\n', FILE_NAME_SIZE);
    if (!uid|| !tid || !fname) return -1;

    // printf("retrieve, uid:%s, tid:%s, fname:%s.\n", uid, tid, fname);
    return 0;
}

int upload(int fd, char* request_message) {
    int index = 4;
    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    char* tid = split(request_message, &index, ' ', TID_SIZE + 1);
    char* fname = split(request_message, &index, ' ', FILE_NAME_SIZE);
    char* size = split(request_message, &index, ' ', 3);
    char* data = split(request_message, &index, '\n', FILE_SIZE);
    if (!uid|| !tid || !fname || !size || !data) return -1;

    // printf("upload, uid:%s, tid:%s, fname:%s, size:%s, data:%s.\n", uid, tid, fname, size, data);
    return 0;
}

int delete(int fd, char* request_message) {
    int index = 4;
    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    char* tid = split(request_message, &index, ' ', TID_SIZE + 1);
    char* fname = split(request_message, &index, '\n', FILE_NAME_SIZE);
    if (!uid|| !tid || !fname) return -1;

    // printf("delete, uid:%s, tid:%s, fname:%s.\n", uid, tid, fname);
    return 0;
}

int remove_all(int fd, char* request_message) {
    int index = 4;
    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    char* tid = split(request_message, &index, '\n', TID_SIZE + 1);
    if (!uid || !tid) return -1;

    // printf("remove, uid:%s, tid:%s.\n", uid, tid);
    return 0;
}

int parse_user_request(int fd, char* request_message) {
    int index = 0;
    char* request_type = split(request_message, &index, ' ', 4);
    if (request_type == NULL) return -1;

    char lst[4] = "LST\0";
    char rtv[4] = "RTV\0";
    char upl[4] = "UPL\0";
    char del[4] = "DEL\0";
    char rem[4] = "REM\0";

    if (strcmp(lst, request_type) == 0) return list(fd, request_message);
    else if (strcmp(rtv, request_type) == 0) return retrieve(fd, request_message);
    else if (strcmp(upl, request_type) == 0) return upload(fd, request_message);
    else if (strcmp(del, request_type) == 0) return delete(fd, request_message);
    else if (strcmp(rem, request_type) == 0) return remove_all(fd, request_message);
    else return -1;
}


int main(int argc, char **argv) {

    if (argc < 1 || argc > 4) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* fs_port = (char*) malloc(sizeof(char) * (PORT_SIZE + 1));
    int verbose = FALSE;
    int port_flag = FALSE;

    int c;
    while ((c = getopt (argc, argv, "p:v")) != -1) {
        switch (c) {
        case 'p':
            port_flag = TRUE;
            strcpy(fs_port, optarg);
            break;
        case 'v':
            verbose = TRUE;
            break;
        default:
            fprintf(stderr, "invalid comand line arguments");
            exit(EXIT_FAILURE);
        }
    }

    if (!port_flag) {
        strcpy(fs_port, FS_PORT);
    }
    if (validate_port(fs_port) == -1) {
        printf("invalid fs_port: %s\n", fs_port);
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    // open comunication sockets for as and users
    // TODO handle error (-1)
    int fd_as = open_udp(fs_port);
    int fd_user = open_tcp(fs_port);
    if (fd_as == -1 || fd_user == -1) {
        printf("can't create socket\n");
        exit(EXIT_FAILURE);
    }

    // vector with current users fd's
    int* users = (int*) malloc(sizeof(int) * MAX_USERS);
    for (int i = 0; i < MAX_USERS; i++) {
        users[i] = -1;
    }

    socklen_t addrlen;
    struct sockaddr_in addr;

    char* in_str = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    FD_ZERO(&inputs); 
    FD_SET(fd_as, &inputs);
    FD_SET(fd_user, &inputs);
    while(TRUE) {
        testfds=inputs;
        timeout.tv_sec=10;
        timeout.tv_usec=0;
        out_fds=select(FD_SETSIZE,&testfds,(fd_set *)NULL,(fd_set *)NULL,&timeout);
        switch(out_fds) {
            case 0:
            // timeout
                break;
            case -1:
                perror("select");
                exit(1);
            default:
                // tcp connection from a new user
                if(FD_ISSET(fd_user,&testfds)) {
                    int newfd;
                    addrlen=sizeof(addr);
                    if ((newfd=accept(fd_user,(struct sockaddr*)&addr, &addrlen))==-1 )/*error*/ exit(1);
                    // TODO lack of space for new users
                    // add new user to user list
                    for (int i = 0; i < MAX_USERS; i++) {
                        if (users[i] == -1) {
                            // printf("added user\n");
                            users[i] = newfd;
                            FD_SET(users[i], &inputs);
                            break;
                        }
                    }

                }
                // check if any active users sent a request
                for (int i = 0; i < MAX_USERS; i++) {
                    if (users[i] != -1 && FD_ISSET(users[i], &testfds)) {
                        // printf("user request\n");
                        n = read (users[i], in_str, BUFFER_SIZE);
                        if(n == -1) exit(EXIT_FAILURE);

                        // TODO handle invalid request
                        int res = parse_user_request(users[i], in_str);
                    }
                }
                
                break;
        }
        
    }

    return 0;
}
