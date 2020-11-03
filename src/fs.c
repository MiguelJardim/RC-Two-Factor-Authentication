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

const char* LST = "LST\0";
const char* RTV = "RTV\0";
const char* UPL = "UPL\0";
const char* DEL = "DEL\0";
const char* REM = "REM\0";

const char* LST_STATUS = "RST\0";
const char* RTV_STATUS = "RTT\0";
const char* UPL_STATUS = "RUP\0";
const char* DEL_STATUS = "RDL\0";
const char* REM_STATUS = "RRM\0";

const char* ERR = "ERR\0";
const char* INV = "INV\0";
const char* OK = "OK\0";
const char* NOK = "NOK\0";

// what messaged to display on verbose mode?
int verbose = FALSE;

int get_file_size(char* path) {
    struct stat st;
    stat(path, &st);
    return (int) st.st_size;
}

char* get_status(char* operation) {
    if (strcmp(operation, LST) == 0) return (char*) LST_STATUS;
    if (strcmp(operation, RTV) == 0) return (char*) RTV_STATUS;
    if (strcmp(operation, UPL) == 0) return (char*) UPL_STATUS;
    if (strcmp(operation, DEL) == 0) return (char*) DEL_STATUS;
    if (strcmp(operation, REM) == 0) return (char*) REM_STATUS;
    return NULL;
}

char* abreviated_form(char* operation) {
    char* output = (char*) malloc(sizeof(char) * 2);
    output[0] = operation[0];
    output[1] = '\0';
    return output;
}

char* user_dirname(char* uid) {
    char* dirname = (char*) malloc(sizeof(char) * (6 + 5 + UID_SIZE));
    if (sprintf(dirname, "USERS/%s", uid) == -1) {
        free(dirname);
        return NULL;
    }
    return dirname;
}

int validate_request(char* uid, char* tid, char* fop, char* fname) {
    char* message = (char*) malloc(sizeof(char) * (4 + UID_SIZE + 1 + TID_SIZE + 2));
    if (sprintf(message, "VLD %s %s\n", uid, tid) == -1) {
        free(message);
        return -1;
    }
    
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
    char error_fop[2] = "E\0";
    if (received_fop == NULL) {
        received_fop = split(answer, &saved, '\n', 2);
        if (!received_fop || strcmp(received_fop, error_fop) == 0 || strcmp(received_fop, fop) != 0) {
            free(answer);
            free(received_fop);
            return -1;
        }
    }
    else {
        char* name = split(answer, &index, '\n', FILE_NAME_SIZE + 1);
        if (fname && ((fname == NULL && name != NULL) || strcmp(name, fname) != 0)) {
            free(received_fop);
            free(name);
            free(answer);
            return -1;
        }
        free(name);
    }
    
    if (strcmp(received_fop, error_fop) == 0 || strcmp(received_fop, fop) != 0) {
        free(received_fop);
        free(answer);
        return -1;
    }
    free(received_fop);
    free(answer);

    return 0;
}

int validate_filename(char* fname) {
    if (!fname) return -1;
    if (strlen(fname) > FILE_NAME_SIZE) return -1;

    int i = 0;
    char c = fname[i++];
    while (c != '.' && c != '\0') {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_')) return -1;
        c = fname[i++];
    }

    if (c != '.') return -1;

    c = fname[i++];
    if (!(c >= 'a' && c <= 'z')) return -1;

    c = fname[i++];
    if (!(c >= 'a' && c <= 'z')) return -1;

    c = fname[i++];
    if (!(c >= 'a' && c <= 'z')) return -1;

    c = fname[i];
    if (c != '\0') return -1;

    return 0;
}

int number_of_files(char* dirname) {
    DIR *d;     
    struct dirent *dir;

    d=opendir(dirname);     
    if(!d) {
        return 0;
    }

    int count = -2;
    while((dir=readdir(d)) !=NULL) {      
        count++;
    }

    return count;

}

char* list(char* uid) {
    if (verbose) printf("listing directory, uid: %s\n", uid);
    // get directory name and check if it exists
    char* dirname = user_dirname(uid);
    if (!dirname) {
        if (verbose) printf("can't get directory name, uid: %s\n", uid);
        free(dirname);
        free(uid);
        return NULL;
    }

    // try to open directory
    DIR *d;     
    struct dirent *dir;     
    d=opendir(dirname);     
    if(!d) {
        if (verbose) {
            printf("can't open user directory, uid: %s\n", uid);
        }
        return NULL;
    }
    
    char ignore_1[2] = ".\0";
    char ignore_2[3] = "..\0";
    int count = 0;
    size_t size = (4 + FILE_NAME_SIZE + 2);
    char* message = (char*) malloc(sizeof(char) * size);
    if (sprintf(message, "RLS") == -1) {
        closedir(d);
        free(message);
        return NULL;
    }
    while((dir=readdir(d)) !=NULL) {      
        if (strcmp(dir->d_name, ignore_1) != 0 && strcmp(dir->d_name, ignore_2) != 0) {
            if (verbose) printf("%s\n", dir->d_name);

            // realloc message if the already allocated memory is not enough
            if (strlen(message) + strlen(dir->d_name) + 2 >= size) {
                message = (char*) realloc(message, size * 2);
                size *= 2;
            }
            // add file name to the message that will be sent to the user
            if (strcat(message, " ") == NULL) {
                closedir(d);
                free(message);
                return NULL;
            }
            if (strcat(message, dir->d_name) == NULL) {
                closedir(d);
                free(message);
                return NULL;
            }
            
            // file path
            char* path = (char*) malloc(sizeof(char) * 100);
            if (sprintf(path, "%s/%s", user_dirname(uid), dir->d_name) == -1) {
                closedir(d);
                free(message);
                free(path);
                return NULL;
            }

            int file_size = get_file_size(path);
            char* size_str = (char*) malloc(sizeof(char) * FILE_SIZE);
            if (sprintf(size_str, " %d", file_size) == -1) {
                closedir(d);
                free(message);
                free(path);
                return NULL;
            }

            if (strcat(message, size_str) == NULL) {
                closedir(d);
                free(message);
                return NULL;
            }

            count++;
        }     
    }

    if (count == 0) {
        free(message);
        closedir(d);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RLS EOF\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    // add '\n' to the message
    if (strcat(message, "\n\0") == NULL) {
        closedir(d);
        free(message);
        return NULL;
    }

    closedir(d);
      
    return message;
}

char* retrieve(char* uid, char* fname) {
    if (verbose) printf("retrieving file, uid: %s, filename: %s\n", uid, fname);
    char* file_path = (char*) malloc(sizeof(char) * (6 + UID_SIZE + 1 + strlen(fname) + 1));
    sprintf(file_path, "USERS/%s/%s", uid, fname);

    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        free(file_path);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RTT EOF\n") == -1) {
            free(message);
            fclose(fp);
            return NULL;
        }
        fclose(fp);
        return message;
    }

    int size = get_file_size(file_path);
    char* data = (char*) malloc(sizeof(char) * (size + 1));

    char* res = fgets(data, size + 1, fp);
    if (!res) {
        free(data);
        fclose(fp);
        return NULL;
    }


    char* message = (char*) malloc(sizeof(char) * (7 + F_SIZE + size + 1));
    if (sprintf(message, "RTT OK %d %s\n", size, data) == -1) {
        free(message);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return message;
}

char* upload(char* uid, char* fname, char* data) {
    if (verbose) printf("uploading file, uid: %s, filename: %s\n", uid, fname);
    char* dirname = (char*) malloc(sizeof(char) * (6 + UID_SIZE + 1));
    if (sprintf(dirname, "USERS/%s", uid) == -1) {
        if (verbose) printf("sprintf error\n");
        free(uid);
        free(dirname);
        free(fname);
        free(data);
        return NULL;
    }

    struct stat st = {0};
    if (stat(dirname, &st) == -1) {
        if (mkdir(dirname, 0700) == -1) {
            if (verbose) printf("upload: can't create directory, uid: %s\n", uid);
            free(uid);
            free(dirname);
            free(fname);
            free(data);
            return NULL;
        }
    }

    // check if the user can upload more files
    if (number_of_files(dirname) >= 15) {
        char* message = (char*) malloc(sizeof(char) * 10);
        if (sprintf(message, "RUP FULL\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    free(dirname);

    char* file_path = (char*) malloc(sizeof(char) * (6 + UID_SIZE + 1 + strlen(fname) + 1));
    sprintf(file_path, "USERS/%s/%s", uid, fname);
    free(uid);

    // check if file already exists
    struct stat buffer;
    if (stat(file_path, &buffer) == 0) {
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RUP DUP\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    FILE *fp;
    fp = fopen(file_path, "wb");
    if (!fp) {
        if (verbose) printf("upload: can't open/create file, uid: %s\n", uid);
        free(fname);
        free(data);
        return NULL;
    }

    if (fputs(data, fp) == EOF) {
        free(fname);
        if (verbose) printf("upload: can't write file, uid: %s\n", uid);
        free(data);
        return NULL;
    }
    fclose(fp);
    free(fname);
    free(data);

    char* message = (char*) malloc(sizeof(char) * 8);
    if (sprintf(message, "RUP OK\n") == -1) {
        free(message);
        return NULL;
    }        
    return message;

}

char* delete(char* uid, char* fname) {
    if (verbose) printf("deleting file, uid: %s, filename: %s\n", uid, fname);
    char* file_path = (char*) malloc(sizeof(char) * (6 + UID_SIZE  + 1 + strlen(fname) + 1));
    sprintf(file_path, "USERS/%s/%s", uid, fname);

    int ret = remove(file_path);
    free(file_path);

    if(ret == 0) {
        char* message = (char*) malloc(sizeof(char) * 8);
        if (sprintf(message, "RDL OK\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    } else {
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RDL EOF\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }


    return NULL;    
}

char* remove_all(char* uid) {
    if (verbose) printf("removing user, uid: %s\n", uid);

    // get directory name and check if it exists
    char* dirname = user_dirname(uid);
    if (!dirname) {
        if (verbose) printf("can't get directory name, uid: %s\n", uid);
        free(dirname);
        free(uid);
        char* message = (char*) malloc(sizeof(char) * 8);
        if (sprintf(message, "DEL NOK\n") == -1) {
            free(message);
            return NULL;
        }
        return message;
    }

    // try to open directory
    DIR *d;     
    struct dirent *dir;     
    d=opendir(dirname);     
    if(!d) {
        if (verbose) {
            printf("can't open user directory, uid: %s\n", uid);
        }
        return NULL;
    }
    
    char ignore_1[2] = ".\0";
    char ignore_2[3] = "..\0";
    while((dir=readdir(d)) !=NULL) {      
        if (strcmp(dir->d_name, ignore_1) != 0 && strcmp(dir->d_name, ignore_2) != 0) {
            char* file_path = (char*) malloc(sizeof(char) * (6 + UID_SIZE  + 1 + strlen(dir->d_name) + 1));
            sprintf(file_path, "USERS/%s/%s", uid, dir->d_name);
            int ret = remove(file_path);
            free(file_path);

            if(ret != 0)  {
                char* message = (char*) malloc(sizeof(char) * 9);
                if (sprintf(message, "REM NOK\n") == -1) {
                    free(message);
                    return NULL;
                }        
                return message;
            }
        }     
    }

    closedir(d);

    if (rmdir(dirname) != 0) {
        char* message = (char*) malloc(sizeof(char) * 10);
        if (sprintf(message, "REM NOK\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    char* message = (char*) malloc(sizeof(char) * 9);
    if (sprintf(message, "REM OK\n") == -1) {
        free(message);
        return NULL;
    }        
    return message;
}

char* parse_user_request(char* request_message) {
    int index = 0;
    char* request_type = split(request_message, &index, ' ', 4);
    if (request_type == NULL) return NULL;

    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    if (validate_uid(uid) == -1) {
        char* message = (char*) malloc(sizeof(char) * 9);
        // ERR message
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    // lst operation only needs uid and tid
    int call = FALSE;
    char* tid = NULL;
    if (strcmp(request_type, LST) == 0 || strcmp(request_type, REM) == 0) {
        tid = split(request_message, &index, '\n', TID_SIZE + 1);
        call = TRUE;
    }
    else tid = split(request_message, &index, ' ', TID_SIZE + 1);

    if (validate_tid(tid) == -1) {
        if (verbose) printf("%s: invalid tid, uid: %s tid: %s\n", request_type, uid, tid);
        free(uid);
        free(tid);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    if (call) {
        if (strcmp(request_type, LST) == 0) {
            free(request_type);
            return list(uid);
        }
        if (strcmp(request_type, REM) == 0) {
            free(request_type);
            return remove_all(uid);
        }
    }

    call = FALSE;
    char* fname;
    if (strcmp(request_type, RTV) == 0 || strcmp(request_type, DEL) == 0) {
        fname = split(request_message, &index, '\n', FILE_NAME_SIZE + 1);
        call = TRUE;
    }
    else fname = split(request_message, &index, ' ', FILE_NAME_SIZE + 1);
    

    // validate the file name
    int result = validate_filename(fname);
    if (result == -1) {
        if (verbose) printf("%s: invalid filename, uid: %s tid: %s\n", request_type, uid, tid);
        free(uid);
        free(tid);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    if (call) {
        if (strcmp(request_type, RTV) == 0) {
            free(request_type);
            return retrieve(uid, fname);
        }
        if (strcmp(request_type, DEL) == 0) {
            free(request_type);
            return delete(uid, fname);
        }
    }

    char* size_str = split(request_message, &index, ' ', 3);
    int size = atoi(size_str);
    free(size_str);
    char* data = split(request_message, &index, '\n', size + 1);

    // check if size is bigger than the limit
    if (size <= 0 || size > FILE_SIZE || !data) {
        if (verbose) printf("%s: invalid arguments, uid: %s\n", request_type, uid);
        free(uid);
        free(tid);
        free(fname);
        free(data);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }
    // validate the operation with the AS
    char* abreviated = abreviated_form(request_type);
    result = validate_request(uid, tid, abreviated, fname);
    free(abreviated);
    if (result == -1) {
        if (verbose) printf("%s: AS refused operation, uid: %s\n", get_status(request_type), uid);
        free(uid);
        free(tid);
        free(fname);
        free(data);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), INV) == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    free(tid);
    free(request_type);

    return upload(uid, fname, data);
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
    int fd_user = open_tcp(fs_port);
    if (fd_user == -1) {
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
                        n = read (users[i], in_str, BUFFER_SIZE);
                        if(n == -1) exit(EXIT_FAILURE);
                        in_str[n] = 0;

                        // TODO handle invalid request
                        char* res = parse_user_request(in_str);
                        if (res) {
                            printf("answer sent to user: %s\n\n", res);
                            n=write(users[i], res, strlen(res));
                            if(n==-1) {
                                // TODO handle error
                                continue;
                            }
                            FD_CLR(users[i], &inputs);
                            close(users[i]);
                            users[i] = -1;
                        }
                    }
                }
                
                break;
        }
        
    }

    return 0;
}
