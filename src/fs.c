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
#include <dirent.h>
#include <sys/stat.h>

#include "../aux/validation.h"
#include "../aux/conection.h"
#include "../aux/constants.h"

int verbose = FALSE;

int list_directory(char *dirname) {
     
    DIR *d;     
    struct dirent *dir;     
    d=opendir(dirname);     
    if(d) {         
        while((dir=readdir(d)) !=NULL) {             
            printf("FILE: %s\n", dir->d_name);         
        }         
        closedir(d);         
        return(1);     
    }     
    else return(-1); 
} 

int validate_request(char* uid, char* tid, char fop, char* fname) {
    char* message = (char*) malloc(sizeof(char) * (4 + UID_SIZE + 1 + TID_SIZE + 2));
    sprintf(message, "VLD %s %s\n", uid, tid);
    
    char* answer = send_udp(message, AS_IP, AS_PORT);
    free(message);

    int index = 0;

    char cnf[4] = "CNF\0";
    char* type = split(answer, &index, ' ', 4);
    if (strcmp(cnf, type) != 0) {
        free(answer);
        free(type);
        return -1;
    }
    free(type);

    char* answer_uid = split(answer, &index, ' ', 6);
    if (strcmp(answer_uid, uid) != 0) {
        free(answer);
        free(answer_uid);
        return -1;
    }
    free(answer_uid);

    char* answer_tid = split(answer, &index, ' ', 5);
    if (strcmp(answer_tid, tid) != 0) {
        free(answer);
        free(answer_tid);
        return -1;
    }
    free(answer_tid);

    int saved = index;
    char* received_fop = split(answer, &index, ' ', 2);
    if (received_fop == NULL) {
        received_fop = split(answer, &saved, '\n', 2);
        if (received_fop == NULL || received_fop[0] == 'E' || received_fop[0] != fop) {
            free(answer);
            free(received_fop);
            return -1;
        }

        char* name = split(answer, &index, '\n', FILE_NAME_SIZE + 1);
        if ((fname == NULL && name != NULL) || name == NULL || strcmp(name, fname) != 0) {
            free(received_fop);
            free(name);
            free(answer);
            return -1;
        }
        free(name);
    }
    
    if (received_fop[0] == 'E' || received_fop[0] != fop) {
        free(received_fop);
        free(answer);
        return -1;
    }
    free(received_fop);
    free(answer);

    return 0;
}

int list(int fd, char* request_message) {
    int index = 4;
    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    char* tid = split(request_message, &index, '\n', TID_SIZE + 1);
    if (!uid || !tid) return -1;
    // printf("list, uid:%s, tid:%s.\n", uid, tid);

    // validate the operation with the AS
    char* message = (char*) malloc(sizeof(char) * (4 + UID_SIZE + 1 + TID_SIZE + 2));
    sprintf(message, "VLD %s %s\n", uid, tid);
    
    int result = validate_request(uid, tid, 'L', NULL);
    if (result == -1) printf("list operation failed\n");

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
    char* size_str = split(request_message, &index, ' ', 3);
    char* data = split(request_message, &index, '\n', FILE_SIZE);
    if (!uid|| !tid || !fname || !size_str || !data) return -1;

    int size = atoi(size_str);
    free(size_str);

    printf("upload, uid:%s, tid:%s, fname:%s, size:%d, data:%s.\n", uid, tid, fname, size, data);

    // validate the operation with the AS
    int result = validate_request(uid, tid, 'U', fname);
    if (result == -1) {
        printf("validation failed\n");
        return -1;
    }

    free(tid);

    char* dirname = (char*) malloc(sizeof(char) * (6 + UID_SIZE));
    sprintf(dirname, "USERS/%s", uid);

    struct stat st = {0};
    if (stat(dirname, &st) == -1) {
        if (mkdir(dirname, 0700) == -1) {
            printf("can't create dir: %s\n", dirname);
            free(uid);
            free(dirname);
            free(fname);
            free(data);
            return -1;
        }
    }

    free(dirname);

    char* file_path = (char*) malloc(sizeof(char) * (6 + UID_SIZE + strlen(fname)));
    sprintf(file_path, "USERS/%s/%s", uid, fname);
    free(uid);

    FILE *fp;
    fp = fopen(file_path, "w");
    if (!fp) {
        free(fname);
        free(data);
        printf("cant open file\n");
        return -1;
    }

    if (fputs(data, fp) == EOF) {
        free(fname);
        free(data);
        printf("cant wirte data\n");
        return -1;
    }
    fclose(fp);
    free(fname);
    free(data);

    printf("upload succesfull\n");

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

    //new directory USERS
    struct stat st = {0};
    if (stat("USERS", &st) == -1) {
        mkdir("USERS", 0700);
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
