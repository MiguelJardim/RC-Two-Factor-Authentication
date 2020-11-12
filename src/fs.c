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
#include <sys/sendfile.h>
#include <fcntl.h>


#include "../aux/validation.h"
#include "../aux/conection.h"
#include "../aux/constants.h"

const char* LST = "LST\0";
const char* RTV = "RTV\0";
const char* UPL = "UPL\0";
const char* DEL = "DEL\0";
const char* REM = "REM\0";

const char* LST_STATUS = "RST\0";
const char* RTV_STATUS = "RRT\0";
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
        if (sprintf(message, "RLS EOF\n") == -1) {
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
    int first = TRUE;
    while((dir=readdir(d)) !=NULL) {      
        if (strcmp(dir->d_name, ignore_1) != 0 && strcmp(dir->d_name, ignore_2) != 0) {
            // realloc message if the already allocated memory is not enough
            if (!first && (strlen(message) + strlen(dir->d_name) + F_SIZE + 2 >= size)) {
                message = (char*) realloc(message, size * 2);
                size *= 2;
            }

            // add file name to the message that will be sent to the user
            if (first) {
                first = FALSE;
                if (sprintf(message, " ") == -1) {
                    closedir(d);
                    free(message);
                    return NULL;
                }
            }
            else {
                if (strcat(message, " ") == NULL) {
                    closedir(d);
                    free(message);
                    return NULL;
                }
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


    char* final_message = (char*) malloc(sizeof(char) * (size + 7));
    if (sprintf(final_message, "RLS %d", count) == -1) {
        closedir(d);
        free(final_message);
        free(message);
        return NULL;
    }
    if (strcat(final_message, message) == NULL) {
        closedir(d);
        free(message);
        free(final_message);
        return NULL;
    }
    free(message);

    closedir(d);
      
    return final_message;
}

char* retrieve(char* uid, char* fname, int fd) {
    if (verbose) printf("retrieving file %s for user %s\n", fname, uid);
    char* file_path = (char*) malloc(sizeof(char) * (6 + UID_SIZE + 1 + strlen(fname) + 1));
    sprintf(file_path, "USERS/%s/%s", uid, fname);

    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        free(file_path);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RRT EOF\n") == -1) {
            free(message);
            fclose(file);
            return NULL;
        }
        fclose(file);
        return message;
    }

    unsigned long long int size = get_file_size(file_path);
    free(file_path);
    int message_size = 7 + F_SIZE + 2;
    char* message = (char*) malloc(sizeof(char) * message_size);
    if (sprintf(message, "RRT OK %llu ", size) == -1) {
        free(message);
        fclose(file);
        return NULL;
    }
 
    int n = write(fd, message, strlen(message));
    free(message);
    if(n <= 0 || !running) {
        return NULL;
    }

    unsigned long long int sent = 0;
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE); 
    while (sent < size) {
        n = fread(buffer, sizeof(char), BUFFER_SIZE, file);
        if (n <= 0 || !running) {
            if (verbose) printf("retrive: can't read data %s\n", uid);
            fclose(file);
            free(buffer);
            return NULL;
        }

        n = write(fd, buffer, n);
        if (n <= 0 || !running) {
            if (verbose) printf("retrive: can't send data %s\n", uid);
            fclose(file);
            free(buffer);
            return NULL;
        }
        sent += n;
        buffer[0] = '\0';
    }
    free(buffer);
    
    // add newline to the end of the message
    char* end = (char*) malloc(sizeof(char) * 2);
    if (sprintf(end, "\n") == -1) {
        free(end);
        fclose(file);
        return NULL;
    }
    n = write(fd, end, 2);
    free(end);
    if(n <= 0 || !running) {
        return NULL;
    }

    fclose(file);

    return NULL;
}

char* upload(char* uid, char* fname, char* data, int data_size, unsigned long long int size, int fd) {
    if (verbose) printf("uploading file %s for user %s\n", fname, uid);
    char* dirname = (char*) malloc(sizeof(char) * (6 + UID_SIZE + 1));
    if (sprintf(dirname, "USERS/%s", uid) == -1) {
        if (verbose) printf("sprintf error\n");
        free(dirname);
        return NULL;
    }

    struct stat st;
    if (stat(dirname, &st) == -1) {
        if (mkdir(dirname, 0700) == -1) {
            if (verbose) printf("upload: can't create directory for user %s\n", uid);
            free(dirname);
            return NULL;
        }
    }

    // check if the user can upload more files
    if (number_of_files(dirname) >= MAX_FILES) {
        free(dirname);
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
    if (stat(file_path, &st) == 0) {
        free(file_path);
        char* message = (char*) malloc(sizeof(char) * 9);
        if (sprintf(message, "RUP DUP\n") == -1) {
            if (verbose) printf("file already exists\n");
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

    if (data_size != 0) {
        if (data_size > (int) size) data_size -= 1;
        if (fwrite(data, 1, data_size, fp) == 0) {
            if (verbose) printf("upload: can't write file for user %s\n", uid);
            fclose(fp);
            return NULL;
        }
    }

    // read rest of data from socket
    int n = -1;
    unsigned long long int received = data_size;
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    while (received < size) {
        n = read(fd, buffer, BUFFER_SIZE);
        if(n <= 0 || !running) {
            if (verbose) printf("upload: can't read data %s\n", uid);
            fclose(fp);
            close(fd);
            free(buffer);
            return NULL;
        }
        received += n;

        if (received > size) n = n - (received - size);

        if (fwrite(buffer, 1, n, fp) == 0) {
            if (verbose) printf("upload: can't write file for user %s\n", uid);
            fclose(fp);
            close(fd);
            free(buffer);
            return NULL;
        }

        buffer[0] = '\0';
    }
    free(buffer);

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
        if (sprintf(message, "RRM NOK\n") == -1) {
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
                if (sprintf(message, "RRM NOK\n") == -1) {
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
        if (sprintf(message, "RRM NOK\n") == -1) {
            free(message);
            return NULL;
        }        
        return message;
    }
    free(dirname);

    char* message = (char*) malloc(sizeof(char) * 8);
    if (sprintf(message, "RRM OK\n") == -1) {
        free(message);
        return NULL;
    }        
    return message;
}

char* parse_user_request(char* request_message, int message_size, int fd) {
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
            if (verbose) printf("%s: AS refused operation for user %s\n", request_type, uid);
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
        free(fname);
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
            if (verbose) printf("%s: AS refused operation for user %s\n", request_type, uid);
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
            char* answer = retrieve(uid, fname, fd);
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

    char* size_str = split(request_message, &index, ' ', F_SIZE);
    unsigned long long int size = 0;
    if (size_str) size = atoi(size_str);
    free(size_str);
    char* data = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    for (int i = index; i < message_size; i++) {
        data[i-index] = request_message[i];
    }

    // check if size is bigger than the limit
    if (size > FILE_SIZE) {
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
        if (verbose) printf("%s: AS refused operation for user %s\n", request_type, uid);
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

    char* answer = upload(uid, fname, data, message_size - index, size, fd);
    free(uid);
    free(fname);
    free(data);
    return answer;
}

void quit(int sig) { 
    if (sig == 2) running = FALSE;

    if (sig == 13) running = FALSE;
}

void handle_user(int newfd) {
    signal(SIGPIPE, quit);

    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);

    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds, n;
    FD_ZERO(&inputs); 
    FD_SET(newfd,&inputs);

    testfds=inputs;
    timeout.tv_sec=10;
    timeout.tv_usec=0;
    out_fds=select_timeout(&testfds, &timeout);
    switch(out_fds) {
        case 0:
            break;
        case -1:
            break;
        default:
            if(FD_ISSET(newfd,&testfds)) {
                n = read(newfd, buffer, BUFFER_SIZE - 1);
                if(n <= 0 || !running) {
                    close(newfd);
                    free(buffer);
                    printf("user disconected - %d\n", user_index % 100);
                    exit(EXIT_FAILURE);
                }
                buffer[n] = '\0';
            }
            break;
    }

    // TODO handle invalid request
    char* res = parse_user_request(buffer, n, newfd);
    free(buffer);
    if (res) {
        n = write(newfd, res, strlen(res));
        if(n <= 0 || !running) {
            // TODO handle error
            free(res);
            close(newfd);
            printf("user disconected - %d\n", user_index % 100);
            exit(EXIT_FAILURE);
        }
    }

    free(res);
    close(newfd);
    printf("user disconected - %d\n", user_index % 100);
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
