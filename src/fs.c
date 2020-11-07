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
#include <signal.h> 

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

int user_index = 0;

// what messaged to display on verbose mode?
int verbose = FALSE;

int running = TRUE;


int validate_request_type(char* type) {
    return (type && (strcmp(type, LST) == 0 || strcmp(type, RTV) == 0 || strcmp(type, UPL) == 0 || strcmp(type, DEL) == 0 || strcmp(type, REM) == 0)) ? 0 : -1;
}

int select_timeout(fd_set* inputs, struct timeval* timeout) {
    int out_fds=select(FD_SETSIZE,inputs,(fd_set *)NULL,(fd_set *)NULL,timeout);
    return out_fds;
}

int get_file_size(char* path) {
    struct stat st;
    stat(path, &st);
    return (int) st.st_size;
}

char* get_status(char* operation) {
    if (operation == NULL) return NULL;
    if (strcmp(operation, LST) == 0) return (char*) LST_STATUS;
    if (strcmp(operation, RTV) == 0) return (char*) RTV_STATUS;
    if (strcmp(operation, UPL) == 0) return (char*) UPL_STATUS;
    if (strcmp(operation, DEL) == 0) return (char*) DEL_STATUS;
    if (strcmp(operation, REM) == 0) return (char*) REM_STATUS;
    return NULL;
}

char* abreviated_form(char* operation) {
    char* output = (char*) malloc(sizeof(char) * 2);
    if (strcmp(operation, REM) == 0) output[0] = 'X';
    else output[0] = operation[0];
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
    if (type == NULL || strcmp(cnf, type) != 0) {
        free(answer);
        free(type);
        return -1;
    }
    free(type);

    char* answer_uid = split(answer, &index, ' ', 6);
    if (answer_uid == NULL || strcmp(answer_uid, uid) != 0) {
        free(answer);
        free(answer_uid);
        return -1;
    }
    free(answer_uid);

    char* answer_tid = split(answer, &index, ' ', 5);
    if (answer_tid == NULL || strcmp(answer_tid, tid) != 0) {
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

    closedir(d);

    return count;

}

char* list(char* uid) {
    if (verbose) printf("listing directory of user %s\n", uid);
    // get directory name and check if it exists
    char* dirname = user_dirname(uid);
    if (!dirname) {
        if (verbose) printf("can't get directory name of user %s\n", uid);
        free(dirname);
        return NULL;
    }

    // try to open directory
    DIR *d;     
    struct dirent *dir;     
    d=opendir(dirname);     
    if(!d) {
        if (verbose) {
            printf("can't open directory of user %s\n", uid);
        }
        closedir(d);
        free(dirname);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "LST EOF\n") == -1) {
            free(message);
            return NULL;
        }
        return message;
    }
    free(dirname);
    
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
            // realloc message if the already allocated memory is not enough
            if (strlen(message) + strlen(dir->d_name) + F_SIZE + 2 >= size) {
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
            char* dirname = user_dirname(uid);
            if (sprintf(path, "%s/%s", dirname, dir->d_name) == -1) {
                closedir(d);
                free(message);
                free(path);
                free(dirname);
                return NULL;
            }
            free(dirname);

            int file_size = get_file_size(path);
            free(path);
            char* size_str = (char*) malloc(sizeof(char) * F_SIZE);
            if (sprintf(size_str, " %d", file_size) == -1) {
                closedir(d);
                free(message);
                free(size_str);
                return NULL;
            }

            if (strcat(message, size_str) == NULL) {
                closedir(d);
                free(message);
                free(size_str);
                return NULL;
            }
            free(size_str);

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
    if (verbose) printf("retrieving file %s for user %s\n", fname, uid);
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
    if (verbose) printf("uploading file %s for user %s\n", fname, uid);
    char* dirname = (char*) malloc(sizeof(char) * (6 + UID_SIZE + 1));
    if (sprintf(dirname, "USERS/%s", uid) == -1) {
        if (verbose) printf("sprintf error\n");
        free(dirname);
        return NULL;
    }

    struct stat st = {0};
    if (stat(dirname, &st) == -1) {
        if (mkdir(dirname, 0700) == -1) {
            if (verbose) printf("upload: can't create directory for user %s\n", uid);
            free(dirname);
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

    // check if file already exists
    struct stat buffer;
    if (stat(file_path, &buffer) == 0) {
        free(file_path);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RUP DUP\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }

    FILE *fp;
    fp = fopen(file_path, "wb");
    free(file_path);
    if (!fp) {
        if (verbose) printf("upload: can't open/create file for user %s\n", uid);
        return NULL;
    }

    if (fputs(data, fp) == EOF) {
        if (verbose) printf("upload: can't write file for user %s\n", uid);
        return NULL;
    }
    fclose(fp);

    char* message = (char*) malloc(sizeof(char) * 8);
    if (sprintf(message, "RUP OK\n") == -1) {
        free(message);
        return NULL;
    }        
    return message;

}

char* delete(char* uid, char* fname) {
    if (verbose) printf("deleting file %s for user %s\n", fname, uid);
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
    }

    char* message = (char*) malloc(sizeof(char) * 9);
    if (sprintf(message, "RDL EOF\n") == -1) {
        free(message);
        return NULL;
    }        
    return message;
}

char* remove_all(char* uid) {
    if (verbose) printf("removing user %s\n", uid);

    // get directory name and check if it exists
    char* dirname = user_dirname(uid);
    if (!dirname) {
        if (verbose) printf("can't get directory name for user %s\n", uid);
        free(dirname);
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
            printf("can't open directory for user %s\n", uid);
        }
        free(dirname);
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
        free(dirname);
        char* message = (char*) malloc(sizeof(char) * 10);
        if (sprintf(message, "REM NOK\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }
    free(dirname);

    char* message = (char*) malloc(sizeof(char) * 9);
    if (sprintf(message, "REM OK\n") == -1) {
        free(message);
        return NULL;
    }        
    return message;
}

char* parse_user_request(char* request_message) {
    int index = 0, result;
    char* request_type = split(request_message, &index, ' ', 4);
    if (validate_request_type(request_type) == -1) {
        free(request_type);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s\n", ERR) == -1) {
            free(message);
            return NULL;
        } 
        return message;
    }

    char* uid = split(request_message, &index, ' ', UID_SIZE + 1);
    if (validate_uid(uid) == -1) {
        char* message = (char*) malloc(sizeof(char) * 9);
        free(uid);
        free(request_type);
        // ERR message
        if (sprintf(message, "%s %s\n", get_status(request_type), NOK) == -1) {
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
        if (verbose) printf("%s: invalid tid, regarding user: %s\n", request_type, uid);
        free(uid);
        free(tid);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(request_type);
            free(message);
            return NULL;
        }        
        free(request_type);
        return message;
    }

    if (call) {
        // validate the operation with the AS
        char* abreviated = abreviated_form(request_type);
        result = validate_request(uid, tid, abreviated, NULL);
        free(abreviated);
        free(tid);
        if (result == -1) {
            if (verbose) printf("%s: AS refused operation for user %s\n", get_status(request_type), uid);
            free(uid);
            char* message = (char*) malloc(sizeof(char) * 9);
            if (sprintf(message, "%s %s\n", get_status(request_type), INV) == -1) {
                free(request_type);
                free(message);
                return NULL;
            }
            free(request_type);   
            return message;
        }

        if (strcmp(request_type, LST) == 0) {
            free(request_type);
            char* answer = list(uid);
            free(uid);
            return answer;
        }
        if (strcmp(request_type, REM) == 0) {
            free(request_type);
            char* answer = remove_all(uid);
            free(uid);
            return answer;
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
    result = validate_filename(fname);
    if (result == -1) {
        if (verbose) printf("%s: invalid filename %s for user %s\n", request_type, fname, uid);
        free(uid);
        free(tid);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(request_type);
            free(message);
            return NULL;
        }
        free(request_type);
        return message;
    }

    if (call) {
        // validate the operation with the AS
        char* abreviated = abreviated_form(request_type);
        result = validate_request(uid, tid, abreviated, fname);
        free(abreviated);
        if (result == -1) {
            if (verbose) printf("%s: AS refused operation for user %s\n", get_status(request_type), uid);
            free(uid);
            free(tid);
            free(fname);
            char* message = (char*) malloc(sizeof(char) * 9);
            if (sprintf(message, "%s %s\n", get_status(request_type), INV) == -1) {
                free(request_type);
                free(message);
                return NULL;
            }
            free(request_type);
            return message;
        }

        free(tid);

        if (strcmp(request_type, RTV) == 0) {
            free(request_type);
            char* answer = retrieve(uid, fname);
            free(uid);
            free(fname);
            return answer;
        }
        if (strcmp(request_type, DEL) == 0) {
            free(request_type);
            char* answer = delete(uid, fname);
            free(uid);
            free(fname);
            return answer;
        }
        free(request_type);
        return NULL;
    }

    char* size_str = split(request_message, &index, ' ', 3);
    int size = -1;
    if (size_str) size = atoi(size_str);
    free(size_str);
    char* data = split(request_message, &index, '\n', size + 1);

    // check if size is bigger than the limit
    if (!size_str || size <= 0 || size > FILE_SIZE || !data) {
        if (verbose) printf("%s: invalid arguments for user %s\n", request_type, uid);
        free(uid);
        free(tid);
        free(fname);
        free(data);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), ERR) == -1) {
            free(request_type);
            free(message);
            return NULL;
        }
        free(request_type);
        return message;
    }
    // validate the operation with the AS
    char* abreviated = abreviated_form(request_type);
    result = validate_request(uid, tid, abreviated, fname);
    free(tid);
    free(abreviated);
    if (result == -1) {
        if (verbose) printf("%s: AS refused operation for user %s\n", get_status(request_type), uid);
        free(uid);
        free(tid);
        free(fname);
        free(data);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "%s %s\n", get_status(request_type), INV) == -1) {
            free(request_type);
            free(message);
            return NULL;
        }
        free(request_type);
        return message;
    }

    free(request_type);

    char* answer = upload(uid, fname, data);
    free(uid);
    free(fname);
    free(data);
    return answer;
}

void quit(int sig) { 
    if (sig == 2) running = FALSE;
} 

void handle_user(int newfd) {
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);

    fd_set inputs;
    struct timeval timeout;
    int out_fds, n;
    FD_ZERO(&inputs); 
    FD_SET(newfd,&inputs);

    timeout.tv_sec=10;
    timeout.tv_usec=0;
    out_fds=select_timeout(&inputs, &timeout);
    switch(out_fds) {
        case 0:
            // timeout
            break;
        case -1:
            break;
        default:
            if(FD_ISSET(newfd,&inputs)) {
                n = read (newfd, buffer, BUFFER_SIZE);
                if(n == -1) exit(EXIT_FAILURE);
                buffer[n] = 0;

                // TODO handle invalid request
                char* res = parse_user_request(buffer);
                if (res) {
                    n=write(newfd, res, strlen(res));
                    free(res);
                    if(n==-1) {
                        // TODO handle error
                        close(newfd);
                        free(buffer);
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            }
    }
    close(newfd);
    printf("user disconected - %d\n", user_index % 100);
    free(buffer);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {

    if (argc < 1 || argc > 4) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, quit);

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
        free(fs_port);
        close(fd_user);
        exit(EXIT_FAILURE);
    }

    //new directory USERS
    struct stat st = {0};
    if (stat("USERS", &st) == -1) {
        mkdir("USERS", 0700);
    }

    socklen_t addrlen;
    struct sockaddr_in addr;

    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds, newfd;
    FD_ZERO(&inputs); 
    FD_SET(fd_user,&inputs);

    while(running) {
        testfds=inputs;
        timeout.tv_sec=1;
        timeout.tv_usec=0;
        out_fds=select_timeout(&testfds, &timeout);
        switch(out_fds) {
            case 0:
                // timeout
                break;
            case -1:
                break;
            default:
                if(FD_ISSET(fd_user,&testfds)) {
                    addrlen=sizeof(addr);

                    if ((newfd=accept(fd_user,(struct sockaddr*)&addr, &addrlen))==-1 ) {
                        /* error */
                        break;
                    }
                    if (verbose) printf("new user connected - %d\n", user_index % 100);

                    if (fork() == 0) {
                        close(fd_user);
                        free(fs_port);
                        handle_user(newfd);
                    }
                    user_index++;
                    close(newfd);
                    break;
                }
        }
    }
    close(fd_user);
    free(fs_port);
    
    return 0;
}
