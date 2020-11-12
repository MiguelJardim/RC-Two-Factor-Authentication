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

#include "../aux/validation.h"
#include "../aux/conection.h"
#include "../aux/constants.h"

int running = TRUE;
int message_to_as = TRUE;
int fd_as;
int fd_fs;

typedef struct request {
    char* uid;
    char* rid;
    char* tid;
    char* fop;
    char* fname;
} Request;

Request* request;

char* fs_ip;
char* fs_port;

int get_file_size(char* path) {
    struct stat st;
    stat(path, &st);
    return (int) st.st_size;
}

int connect_tcp(char* ip, char* port) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints, *res;

    fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd==-1) return -1;

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET;
    hints.ai_socktype=SOCK_STREAM;
    errcode= getaddrinfo(ip, port, &hints,&res);
    if(errcode!=0) return -1;

    n= connect (fd,res->ai_addr,res->ai_addrlen);
    if(n==-1) return -1;

    freeaddrinfo(res); 

    return fd;

}

int four_digit_number_generator() {
    return rand() % 9000 + 1000;
}


char* login_command(char* input, int index) {
    int input_index = index;   
    char ok[9] = "RLO OK\n\0"; 

    //user already logged in
    if (request->uid != NULL) {
        printf("User already logged in\n");
        return NULL;
    }
        
    // read ist id
    char* uid = split(input, &input_index, ' ', UID_SIZE + 1);
    if (uid == NULL) {
        printf("invalid uid\n");
        free(uid);
        return NULL;
    }
    if (validate_uid(uid) == -1) {
        printf("invalid uid: %s\n", uid);
        free(uid);
        return NULL;
    }
    // read password
    char* password = split(input, &input_index, '\n', PASSWORD_SIZE + 1);
    if (password == NULL) {
        printf("invalid password\n");
        free(uid);
        free(password);
        return NULL;
    }
    if (validate_password(password) == -1) {
        printf("invalid password: %s\n", password);
        free(uid);
        free(password);
        return NULL;
    }
    // LOG UID pass
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "LOG %s %s\n", uid, password) < 0) {
        free(message);
        free(uid);
        free(password);
        printf("Sprintf ERROR\n");
        return NULL;
    }
    free(password);

    int n = write (fd_as, message, strlen(message));
    if (n == -1) {
        printf("Cant send message to as\n");
        free(message);
        return NULL; 
    }
    n = read(fd_as, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("Cant read message from as\n");
        return NULL; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        if (request->uid == NULL) request->uid = (char*) malloc(sizeof(char) * (UID_SIZE + 1));
        strcpy(request->uid, uid);
    }
    free(uid);

    return message;
}

char* req_command(char* input, int index) {
    int input_index = index;
    char ok[9] = "RRQ OK\n\0"; // deu ok
    char* message = NULL;
    char* filename = NULL;
    int rid;

    if (request->uid == NULL) {
        printf("Not logged in\n");
        return NULL; 
    }
        

    // read fop
    char* fop = split(input, &input_index, ' ', 2);
    if (fop == NULL) {
        int input_index = index;
        fop = split(input, &input_index, '\n', 2);
        if (fop == NULL) {
            printf("invalid file operation\n");
            free(fop);
            return NULL;  
        }
        int f = validate_fop(fop);
        if (f == -1) {
            printf("Unexpected operation\n");
            free(fop);
            return NULL;
        }
        else if (f == 2) {
            printf("This operation needs a file name\n");
            free(fop);
            return NULL;    
        }

        rid = four_digit_number_generator();
        // REQ UID RID Fop
        message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
        if (sprintf(message, "REQ %s %d %s\n", request->uid, rid, fop) < 0) {
            free(message);
            free(fop);
            printf("Sprintf ERROR\n");
            return NULL;
        }
    }
    else {
        int f = validate_fop(fop);
        if (f == -1) {
            printf("Unexpected operation\n");
            free(fop);
            return NULL;
        }
        else if (f == 1) {
            printf("This operation doesnt need a file name\n");
            free(fop);
            return NULL;    
        }

        filename = split(input, &input_index, '\n', FILE_NAME_SIZE + 1);
        printf("%s\n", filename);
        if (filename == NULL) {
            printf("invalid filename\n");
            free(fop);
            free(filename);
            return NULL;
        }

        rid = four_digit_number_generator();
        // REQ UID RID Fop Fname
        message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
        if (sprintf(message, "REQ %s %d %s %s\n", request->uid, rid, fop, filename) < 0) {
            free(message);
            free(fop);
            free(filename);
            printf("sprintf error\n");
            return NULL;
        }
    }

    int n = write (fd_as, message, strlen(message));
    if (n == -1) {
        printf("Cant send message to as\n");
        free(message);
        free(fop);
        return NULL; 
    }
    n = read(fd_as, message, BUFFER_SIZE);
    if (n == -1) {
        printf("Cant read message from as\n");
        free(message);
        free(fop);
        return NULL; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        if (request->rid == NULL) request->rid = (char*) malloc(sizeof(char) * (RID_SIZE + 1));
        sprintf(request->rid, "%d", rid);
        if (request->fop == NULL) request->fop = (char*) malloc(sizeof(char) * 2);
        sprintf(request->fop, "%s", fop);
        if (validate_fop(fop) == 2) {
            if (request->fname == NULL) request->fname = (char*) malloc(sizeof(char) * (FILE_NAME_SIZE + 1));
            sprintf(request->fname, "%s", filename);
            free(filename);
        }
    }
    free(fop);
    return message;
}

char* val_command(char* input, int index) {
    int input_index = index;
    char failed[7] = "RAU 0\n\0";

    if (request->uid == NULL || request->rid == NULL) {
        if (request->uid == NULL) printf("Not logged in\n");
        if (request->rid == NULL) printf("No request made\n");
        return NULL;
    }

    // read VC
    char* vc = split(input, &input_index, '\n', VC_SIZE + 1);
    if (vc == NULL) {
        printf("invalid vc\n");
        free(vc);
        return NULL;
    }
    if (validate_vc(vc) == -1) {
        printf("invalid vc\n");
        free(vc);
        return NULL; 
    }
    // AUT UID RID VC
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "AUT %s %s %s\n", request->uid, request->rid, vc) < 0) {
        free(message);
        free(vc);
        printf("Sprintf ERROR\n");
        return NULL;
    }
    free(vc);

    int n = write (fd_as, message, strlen(message));
    if (n == -1) {
        printf("Cant send message to as\n");
        free(message);
        return NULL; 
    }
    n = read(fd_as, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("Cant read message from as\n");
        return NULL; 
    }
    message[n] = 0;

    if (strcmp(message, failed) != 0) {
        if (request->tid == NULL) request->tid = (char*) malloc(sizeof(char) * (TID_SIZE + 1));
        int aut_index = 4;
        char* tid = split(message, &aut_index, '\n', TID_SIZE + 1);
        strcpy(request->tid, tid);
        free(tid);
    }

    return message;
}


char* list_command() {
    char failed[9] = "RLS EOF\n\0";
    char error[9] = "RLS ERR\n\0";

    // LST UID TID
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "LST %s %s\n", request->uid, request->tid) < 0) {
        free(message);
        printf("Sprintf ERROR\n");
        return NULL;
    }
    fd_fs = connect_tcp(fs_ip, fs_port);

    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    int n = write(fd_fs, message, strlen(message));

    if(n == -1) {
        printf("remove failed\n");
        return NULL;
    }
    //RLS N[ Fname Fsize]*
    n = read(fd_fs, message, BUFFER_SIZE);

    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return NULL; 
    }
    message[n] = 0;
    if (strcmp(message, failed) == 0) {
        printf("Request cannot be answered.\n");

    }else if(strcmp(message, error) == 0){
        printf("Failed list all files.\n");
        
    }else{
        int i = atoi(message[5]);
        //for(...
    }


    return message;
}

char* retrieve_command(char* input, int index) {
    int input_index = index;

    char* filename = split(input, &input_index, ' ', 20);
    if (filename == NULL) {
        printf("invalid file name\n");
        free(filename);
        return NULL;
    }
    // RTV UID TID Fname
    char* message = (char*) malloc(sizeof(char) * 45);
    if (sprintf(message, "RTV %s %s %s\n", request->uid, request->tid, filename) < 0) {
        free(message);
        free(filename);
        printf("Sprintf ERROR\n");
        return NULL;
    }
    free(filename);
    return message;
}

char* upload(char* input, int index) {
    char ok[9] = "RUP OK\n\0";
    char dup[10] = "RUP DUP\n\0";
    char full[11] = "RUP FULL\n\0";
    char nok[10] = "RUP NOK\n\0";

    if (request->tid == NULL) {
        printf("upload failed\n");
        return NULL;
    }

    int input_index = index;

    char* filename = split(input, &input_index, '\n', FILE_NAME_SIZE + 1);
    if (filename == NULL || request->fname == NULL || strcmp(filename, request->fname) != 0) {
        printf("invalid file name\n");
        free(filename);
        return NULL;
    }

    // open file
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        free(filename);
        printf("can't open file\n");
        return NULL;
    }

    // get file size
    unsigned long long int size = get_file_size(filename);

    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "UPL %s %s %s %llu ", request->uid, request->tid, filename, size) < 0) {
        free(message);
        free(filename);
        printf("sprintf error\n");
        return NULL;
    }
    free(filename);

    fd_fs = connect_tcp(fs_ip, fs_port);
    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    // write the first part of the message
    int n = write(fd_fs, message, strlen(message));
    free(message);
    if(n == -1) {
        printf("upload failed\n");
        return NULL;
    }

    // read and write de file contents on the socket
    unsigned long long int sent = 0;
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE); 
    while (sent < size) {
        n = fread(buffer, sizeof(char), BUFFER_SIZE, file);
        if (n == -1) {
            printf("retrive: can't read data\n");
            fclose(file);
            free(buffer);
            return NULL;
        }

        n = write(fd_fs, buffer, n);
        if (n == -1) {
            printf("retrive: can't send data\n");
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
        printf("upload failed\n");
        return NULL;
    }
    n = write(fd_fs, end, 2);
    free(end);
    if(n == -1) {
        printf("upload failed\n");
        return NULL;
    }
    fclose(file);

    n = read(fd_fs, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return NULL; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        printf("File upload well secceeded.\n");
    }
    if (strcmp(message, dup) == 0) {
        printf("File already exists.\n");
    }
    if (strcmp(message, full) == 0) {
        printf("Failed uploading file.\n
                Server already reached full capacity.\n");
    }
    if (strcmp(message, nok) == 0) {
        printf("Failed uploading file.\n");
    }
    close(fd_fs);
    return NULL;
}

char* delete_command(char* input, int index) {
    int input_index = index;
    char ok[9] = "RDL OK\n\0";

    char* filename = split(input, &input_index, ' ', FILE_NAME_SIZE + 1);
    if (filename == NULL) {
        printf("invalid filename\n");
        free(filename);
        return NULL;
    }
    // DEL UID TID Fname
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "DEL %s %s %s\n", request->uid, request->tid, filename) < 0) {
        free(message);
        free(filename);
        printf("Sprintf ERROR\n");
        return NULL;
    }
    free(filename);

    fd_fs = connect_tcp(fs_ip, fs_port);

    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    int n = write(fd_fs, message, strlen(message));
    free(message);
    if(n == -1) {
        printf("delete failed\n");
        return NULL;
    }

    n = read(fd_fs, message, BUFFER_SIZE);

    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return NULL; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        printf("File deletion well succeeded\n");
    }else{
        printf("Failed deleting file\n");
    }
    close(fd_fs);
    return NULL;
}

char* remove_command() {
    char ok[9] = "RRM OK\n\0";

    // REM UID TID
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);

    if (sprintf(message, "REM %s %s\n", request->uid, request->tid) < 0) {
        free(message);
        printf("Sprintf ERROR\n");
        return NULL;
    }
    free(message);

    fd_fs = connect_tcp(fs_ip, fs_port);

    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    int n = write(fd_fs, message, strlen(message));

    if(n == -1) {
        printf("remove failed\n");
        return NULL;
    }
    n = read(fd_fs, message, BUFFER_SIZE);

    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return NULL; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        printf("All files removed.\n
                All directories removed.\n
                User's information deleted from server.\n");
    }else{
        printf("Failed removing files.\n
                Failed removing directories.\n
                Failed deleting user's information from server.\n");
    }
    close(fd_fs);
    return NULL;
}

void disconnect_user() {
    running = FALSE;
}

char* treat_command(char* input) {
    int input_index = 0;

    char exit[5] = "exit\0";
    char* aux = split(input, &input_index, '\n', 5);
    if (aux == NULL)
        free(aux);
    else {
        if (strcmp(aux, exit) != 0)
            free(aux);
        else {
            disconnect_user();
            free(aux);
            return NULL;
        }
    }

    input_index = 0;
    char login[6] = "login\0";
    aux = split(input, &input_index, ' ', 6);
    if (aux == NULL)
        free(aux);
    else {
        if (strcmp(aux, login) != 0)
            free(aux);
        else {
            char* message = login_command(input, input_index);
            free(aux);
            return message;
        }
    } 

    input_index = 0;
    char req[4] = "req\0";
    aux = split(input, &input_index, ' ', 4);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, req) != 0))
            free(aux);
        else {
            printf("aqui\n");
            char* message = req_command(input, input_index);
            free(aux);
            return message;
        }
    }

    input_index = 0;
    char val[4] = "val\0";
    aux = split(input, &input_index, ' ', 4);
    if (aux == NULL)
        free(aux);
    else {
        if (strcmp(aux, val) != 0)
            free(aux);
        else {
            char* message = val_command(input, input_index);
            free(aux);
            return message;
        }
    }   
    
    input_index = 0;
    char list[5] = "list\0", l[2] = "l\0";
    aux = split(input, &input_index, '\n', 5);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, list) != 0) && (strcmp(aux, l) != 0))
            free(aux);
        else {
            //TODO
            return NULL;
        } 
    }  
    
    input_index = 0;
    char retrieve[9] = "retrieve\0";
    char r[2] = "r\0";
    aux = split(input, &input_index, ' ', 9);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, retrieve) != 0) && (strcmp(aux, r) != 0))
            free(aux);
        else {
            //TODO
            return NULL;
        }
    }
    
    input_index = 0;
    char upload_str[7] = "upload\0";
    char u[2] = "u\0";
    aux = split(input, &input_index, ' ', 7);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, upload_str) != 0) && (strcmp(aux, u) != 0))
            free(aux);
        else {
            char* answer = upload(input, input_index);
            free(answer);
            return NULL;
        }
    }  
    
    input_index = 0;
    char delete[7] = "delete\0", d[2] = "d\0";
    aux = split(input, &input_index, ' ', 7);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, delete) != 0) && (strcmp(aux, d) != 0))
            free(aux);
        else {
            char* answer = delete_command(input, input_index);
            free(answer);
            return NULL;
        }
    }
    
    input_index = 0;
    char remove[7] = "remove\0";
    char x[2] = "x\0";
    aux = split(input, &input_index, '\n', 7);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, remove) != 0) && (strcmp(aux, x) != 0))
            free(aux);
        else {
            char* answer = remove_command();
            free(answer);
            return NULL;
        }
    }

    printf("Invalid Command\n");
    return NULL;
}

int main(int argc, char **argv) {
    // ./user[-n ASIP] [-p ASport] [-m FSIP] [-q FSport]

    if (argc < 1 || argc > 9) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    request = (Request*) malloc(sizeof(Request)); 
    request->fname = NULL;
    request->fop = NULL;
    request->tid = NULL;
    request->uid = NULL;
    request->rid = NULL;

    int as_ip_flag = FALSE,
        as_port_flag = FALSE,
        fs_ip_flag = FALSE,
        fs_port_flag = FALSE;

    char* as_ip = (char*) malloc(sizeof(char) * (IP_MAX_SIZE + 1));
    char* as_port = (char*) malloc(sizeof(char) * (PORT_SIZE + 1));

    fs_ip = (char*) malloc(sizeof(char) * (IP_MAX_SIZE + 1));
    fs_port = (char*) malloc(sizeof(char) * (PORT_SIZE + 1));

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
            printf("unexpected arguments\n");
            exit(EXIT_FAILURE);
        }
    }

    if (as_port_flag == FALSE) {
        strcpy(as_port, AS_PORT);
    }
    if (validate_port(as_port) == -1) {
        printf("invalid as_port\n");
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    if (as_ip_flag == FALSE) {
        strcpy(as_ip, AS_IP);
    }
    if (validate_ip(as_ip) == -1) {
        printf("invalid as_ip: %s\n", as_ip);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }
    
    
    if (fs_port_flag == FALSE) {
        strcpy(fs_port, FS_PORT);
    }
    if (validate_port(fs_port) == -1) {
        printf("invalid as_port\n");
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    if (fs_ip_flag == FALSE) {
        strcpy(fs_ip, FS_IP);
    }
    if (validate_ip(fs_ip) == -1) {
        printf("invalid as_ip: %s\n", fs_ip);
        free(as_ip);
        free(as_port);
        free(fs_ip);
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    fd_as = connect_tcp(as_ip, as_port);
    if (fd_as == -1) {
        printf("can't create socket\n");
        free(as_port);
        exit(EXIT_FAILURE);
    }

    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    char* in_str = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    FD_ZERO(&inputs);
    FD_SET(0, &inputs);
    while(running) {
        testfds = inputs;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        out_fds = select(FD_SETSIZE, &testfds, (fd_set *)NULL, (fd_set *)NULL, &timeout);
        switch(out_fds) {
            case 0:
                break;
            case -1:
                perror("select");
                exit(EXIT_FAILURE);
            default:
                if(FD_ISSET(0, &testfds)) {
                    if (( n = read(0, in_str, BUFFER_SIZE))!= 0) {
                        if (n == -1) {
                            printf("cant read from stdin\n");
                            exit(1); 
                        } 
                        in_str[n]=0;
                        char* answer = treat_command(in_str);
                        if (answer != NULL) printf("%s", answer);
                        free(answer);
                    }
                }
                break;  
        }
    }

    close(fd_as);
    close(fd_fs);
    if (request->uid != NULL) free(request->uid);
    if (request->tid != NULL) free(request->tid);
    if (request->rid != NULL) free(request->rid);
    if (request->fname != NULL) free(request->fname);
    if (request->fop != NULL) free(request->fop);
    free(request);
    free(as_ip);
    free(as_port);
    free(fs_ip);
    free(fs_port);
    free(in_str);

    return 0;
}

