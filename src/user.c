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

int logged_in = FALSE;

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


void login(char* input, int index) {
    int input_index = index;   
    char ok[9] = "RLO OK\n\0"; 

    //user already logged in
    if (request->uid != NULL) {
        printf("User already logged in\n");
        return;
    }
        
    // read ist id
    char* uid = split(input, &input_index, ' ', UID_SIZE + 1);
    if (uid == NULL) {
        printf("invalid uid\n");
        free(uid);
        return;
    }
    if (validate_uid(uid) == -1) {
        printf("invalid uid: %s\n", uid);
        free(uid);
        return;
    }
    // read password
    char* password = split(input, &input_index, '\n', PASSWORD_SIZE + 1);
    if (password == NULL) {
        printf("invalid password\n");
        free(uid);
        free(password);
        return;
    }
    if (validate_password(password) == -1) {
        printf("invalid password: %s\n", password);
        free(uid);
        free(password);
        return;
    }
    // LOG UID pass
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "LOG %s %s\n", uid, password) < 0) {
        free(message);
        free(uid);
        free(password);
        printf("Sprintf ERROR\n");
        return;
    }
    free(password);

    int n = write (fd_as, message, strlen(message));
    if (n == -1) {
        printf("Cant send message to as\n");
        free(message);
        return; 
    }
    n = read(fd_as, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("Cant read message from as\n");
        return; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        if (request->uid == NULL) request->uid = (char*) malloc(sizeof(char) * (UID_SIZE + 1));
        strcpy(request->uid, uid);
        logged_in = TRUE;
        printf("Login successful.\n");
        free(uid);
        free(message);
        return;
    }

    free(message);
    free(uid);
    printf("Login failed.\n");

    return;
}

void request_operation(char* input, int index) {
    int input_index = index;
    char ok[9] = "RRQ OK\n\0"; // deu ok
    char* message = NULL;
    char* filename = NULL;
    int rid;

    if (request->uid == NULL) {
        printf("Not logged in.\n");
        return; 
    }
        

    // read fop
    char* fop = split(input, &input_index, ' ', 2);
    if (fop == NULL) {
        int input_index = index;
        fop = split(input, &input_index, '\n', 2);
        if (fop == NULL) {
            printf("invalid file operation\n");
            free(fop);
            return;  
        }
        int f = validate_fop(fop);
        if (f == -1) {
            printf("Unexpected operation\n");
            free(fop);
            return;
        }
        else if (f == 2) {
            printf("This operation needs a file name\n");
            free(fop);
            return;    
        }

        rid = four_digit_number_generator();
        // REQ UID RID Fop
        message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
        if (sprintf(message, "REQ %s %d %s\n", request->uid, rid, fop) < 0) {
            free(message);
            free(fop);
            printf("sprintf error\n");
            return;
        }
    }
    else {
        int f = validate_fop(fop);
        if (f == -1) {
            printf("Unexpected operation\n");
            free(fop);
            return;
        }
        else if (f == 1) {
            printf("This operation doesnt need a file name\n");
            free(fop);
            return;    
        }

        filename = split(input, &input_index, '\n', FILE_NAME_SIZE + 1);
        if (filename == NULL) {
            printf("Invalid filename.\n");
            free(fop);
            free(filename);
            return;
        }

        rid = four_digit_number_generator();
        // REQ UID RID Fop Fname
        message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
        if (sprintf(message, "REQ %s %d %s %s\n", request->uid, rid, fop, filename) < 0) {
            free(message);
            free(fop);
            free(filename);
            printf("sprintf error\n");
            return;
        }
    }

    int n = write (fd_as, message, strlen(message));
    if (n == -1) {
        printf("Cant send message to as\n");
        if (filename != NULL) free(filename);
        free(message);
        free(fop);
        return; 
    }
    n = read(fd_as, message, BUFFER_SIZE);
    if (n == -1) {
        printf("Cant read message from as\n");
        if (filename != NULL) free(filename);
        free(message);
        free(fop);
        return; 
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
        }
        printf("Request successful.\n");
        if (filename != NULL) free(filename);
        free(fop);
        free(message);
        return;
    }
    if (filename != NULL) free(filename);
    free(fop);
    free(message);
    printf("Request failed.\n");
    return;
}

void validate_operation(char* input, int index) {
    int input_index = index;
    char failed[7] = "RAU 0\n\0";

    if (request->uid == NULL || request->rid == NULL) {
        if (request->uid == NULL) printf("Not logged in\n");
        if (request->rid == NULL) printf("No request made\n");
        return;
    }

    // read VC
    char* vc = split(input, &input_index, '\n', VC_SIZE + 1);
    if (vc == NULL) {
        printf("invalid vc\n");
        free(vc);
        return;
    }
    if (validate_vc(vc) == -1) {
        printf("invalid vc\n");
        free(vc);
        return; 
    }
    // AUT UID RID VC
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "AUT %s %s %s\n", request->uid, request->rid, vc) < 0) {
        free(message);
        free(vc);
        printf("Sprintf ERROR\n");
        return;
    }
    free(vc);

    int n = write (fd_as, message, strlen(message));
    if (n == -1) {
        printf("Cant send message to as\n");
        free(message);
        return; 
    }
    n = read(fd_as, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("Cant read message from as\n");
        return; 
    }
    message[n] = 0;

    if (strcmp(message, failed) != 0) {
        if (request->tid == NULL) request->tid = (char*) malloc(sizeof(char) * (TID_SIZE + 1));
        int aut_index = 4;
        char* tid = split(message, &aut_index, '\n', TID_SIZE + 1);
        strcpy(request->tid, tid);
        free(tid);
        free(message);
        printf("Validation successful.\n");
        return;
    }
    free(message);
    printf("Validation failed.\n");

    return;
}


void list() {
    char failed[9] = "RLS EOF\n\0";
    char error[9] = "RLS ERR\n\0";

    if (!logged_in || request->tid == NULL) return;

    // LST UID TID
    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "LST %s %s\n", request->uid, request->tid) < 0) {
        free(message);
        printf("sprintf error\n");
        return;
    }
    fd_fs = connect_tcp(fs_ip, fs_port);
    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        free(message);
        exit(EXIT_FAILURE);
    }

    int n = write(fd_fs, message, strlen(message));
    if(n == -1) {
        close(fd_fs);
        free(message);
        printf("list failed\n");
        return;
    }
    message[0] = '\0';

    n = read(fd_fs, message, BUFFER_SIZE);
    if (n == -1) {
        close(fd_fs);
        free(message);
        printf("can't read message from fs\n");
        return; 
    }
    message[n] = '\0';
    if (strcmp(message, failed) == 0) {
        close(fd_fs);
        free(message);
        printf("No files to list.\n");
        return;

    }
    if(strcmp(message, error) == 0){
        free(message);
        close(fd_fs);
        printf("Invalid request.\n");
        return;
    }

    char rls[4] = "RLS\0";
    int index= 0;
    char* aux = split(message, &index, ' ', 4);
    if (aux == NULL || strcmp(aux, rls) != 0) {
        printf("Invalid answer from file server.\n");
        close(fd_fs);
        free(message);
        free(aux);
        return;
    }
    free(aux);

    // number of files
    aux = split(message, &index, ' ', 3);
    if (aux == NULL) {
        printf("Invalid answer from file server.\n");
        close(fd_fs);
        free(aux);
        free(message);
        return;
    }
    if (strlen(aux) > 2 || !is_number(aux)) {
        printf("Invalid answer from file server.\n");
        close(fd_fs);
        free(aux);
        free(message);
        return;
    }

    int num_files = atoi(aux);
    free(aux);

    char* size;
    int i;
    for (i = 1; i < num_files; i++) {
        aux = split(message, &index, ' ', FILE_NAME_SIZE + 1);
        if (aux == NULL) {
            printf("Invalid answer from file server.\n");
            close(fd_fs);
            free(aux);
            free(message);
            return;
        }
        size = split(message, &index, ' ', F_SIZE + 1);
        if (strlen(size) > F_SIZE || !is_number(size)) {
            printf("Invalid answer from file server.\n");
            close(fd_fs);
            free(aux);
            free(size);
            free(message);
            return;
        }
        printf("%d. %s with %s bytes\n", i, aux, size);
        free(aux);
        free(size);
    }

    aux = split(message, &index, ' ', FILE_NAME_SIZE + 1);
    if (aux == NULL) {
        printf("Invalid answer from file server.\n");
        close(fd_fs);
        free(aux);
        free(size);
        free(message);
        return;
    }
    size = split(message, &index, '\n', F_SIZE + 1);
    if (size == NULL || strlen(size) > F_SIZE || !is_number(size)) {
        printf("Invalid answer from file server.\n");
        close(fd_fs);
        free(aux);
        free(size);
        free(message);
        return;
    }
    close(fd_fs);
    printf("%d. %s with %s bytes\n", i, aux, size);
    free(message);
    free(size);
    free(aux);

    return;
}

void retrieve(char* input, int index) {
    int input_index = index;

    if (!logged_in || request->uid == NULL || request->tid == NULL) return;

    char* filename = split(input, &input_index, '\n', FILE_NAME_SIZE + 1);
    if (filename == NULL || validate_filename(filename) == -1 || strcmp(filename, request->fname) != 0) {
        printf("Invalid filename.\n");
        free(filename);
        return;
    }

    struct stat st;
    // check if file already exists
    if (stat(filename, &st) == 0) {
        free(filename);
        printf("File already retrieved.\n");
        return;
    }

    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "RTV %s %s %s\n", request->uid, request->tid, filename) < 0) {
        free(message);
        free(filename);
        printf("sprintf error\n");
        return;
    }

    fd_fs = connect_tcp(fs_ip, fs_port);
    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        free(message);
        exit(EXIT_FAILURE);
    }

    // send request message
    int n = write(fd_fs, message, strlen(message));
    if (n <= 0) {
        free(message);
        free(filename);
        printf("Connection error.\n");
        close(fd_fs);
        return;
    }
    message[0] = '\0';

    n = read(fd_fs, message, BUFFER_SIZE);
    if (n <= 0) {
        free(message);
        free(filename);
        printf("Connection error.\n");
        close(fd_fs);
        return;
    }

    int message_index = 0;
    char rrt[4] = "RRT\0";
    char* type = split(message, &message_index, ' ', 4);
    if (type == NULL || strcmp(type, rrt) != 0) {
        printf("%s\n", type);
        free(message);
        free(filename);
        free(type);
        printf("Unexpected response from FS.\n");
        close(fd_fs);
        return;
    }
    free(type);

    char ok[3] = "OK\0";
    char* status = split(message, &message_index, ' ', 3);
    if (status == NULL || strcmp(status, ok) != 0) {
        free(message);
        free(filename);
        free(status);
        printf("Unexpected response from FS.\n");
        close(fd_fs);
        return;
    }
    free(status);

    char* size_str = split(message, &message_index, ' ', F_SIZE + 1);
    if (size_str == NULL || !is_number(size_str)) {
        free(message);
        free(filename);
        free(size_str);
        printf("Unexpected response from FS.\n");
        close(fd_fs);
        return;
    }
    free(message);

    unsigned long long int size = (unsigned long long int) strtol(size_str, NULL, 10);
    free(size_str);

    char* data = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    for (int i = message_index; i < n; i++) {
        data[i-message_index] = message[i];
    }
    unsigned long long int received = n - message_index;

    FILE *fp;
    fp = fopen(filename, "wb");
    free(filename);
    if (!fp) {
        printf("Can't open file.\n");
        close(fd_fs);
        return;
    }

    if (received > 0) {
        if (fwrite(data, 1, received, fp) == 0) {
            printf("Upload failed.\n");
            fclose(fp);
            free(data);
            close(fd_fs);
            return;
        }
    }
    free(data);

    // read rest of data from socket
    n = -1;
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    while (received < size) {
        n = read(fd_fs, buffer, BUFFER_SIZE);
        if(n == -1) {
            printf("Connection error.\n");
            fclose(fp);
            close(fd_fs);
            free(buffer);
            return;
        }
        received += n;

        if (received > size) n = n - (received - size);

        if (fwrite(buffer, 1, n, fp) == 0) {
            printf("Connection error.\n");
            fclose(fp);
            close(fd_fs);
            free(buffer);
            return;
        }

        buffer[0] = '\0';
    }
    free(buffer);

    fclose(fp);
    close(fd_fs);
    printf("Retrieve successful.\n");
    return;
}

void upload(char* input, int index) {
    char ok[9] = "RUP OK\n\0";
    char dup[10] = "RUP DUP\n\0";
    char full[11] = "RUP FULL\n\0";
    char nok[10] = "RUP NOK\n\0";

    if (!logged_in || request->tid == NULL) {
        printf("Upload failed.\n");
        return;
    }

    int input_index = index;

    char* filename = split(input, &input_index, '\n', FILE_NAME_SIZE + 1);
    if (filename == NULL || request->fname == NULL || strcmp(filename, request->fname) != 0) {
        printf("Invalid filename.\n");
        free(filename);
        return;
    }

    // open file
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        free(filename);
        printf("Can't open file.\n");
        return;
    }

    // get file size
    unsigned long long int size = get_file_size(filename);

    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "UPL %s %s %s %llu ", request->uid, request->tid, filename, size) < 0) {
        free(message);
        free(filename);
        printf("sprintf error\n");
        return;
    }
    free(filename);

    fd_fs = connect_tcp(fs_ip, fs_port);
    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        free(message);
        exit(EXIT_FAILURE);
    }

    // write the first part of the message
    int n = write(fd_fs, message, strlen(message));
    if(n == -1) {
        printf("Upload failed.\n");
        free(message);
        return;
    }

    // read and write de file contents on the socket
    unsigned long long int sent = 0;
    char* buffer = (char*) malloc(sizeof(char) * BUFFER_SIZE); 
    while (sent < size) {
        n = fread(buffer, sizeof(char), BUFFER_SIZE, file);
        if (n == -1) {
            printf("upload: can't read data\n");
            fclose(file);
            free(buffer);
            free(message);
            return;
        }

        n = write(fd_fs, buffer, n);
        if (n == -1) {
            printf("upload: can't send data\n");
            fclose(file);
            free(buffer);
            free(message);
            return;
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
        free(message);
        printf("upload failed\n");
        return;
    }
    n = write(fd_fs, end, 2);
    free(end);
    if(n == -1) {
        printf("upload failed\n");
        free(message);
        return;
    }
    fclose(file);

    message[0] = '\0';
    n = read(fd_fs, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        printf("Upload successful.\n");
    }
    if (strcmp(message, dup) == 0) {
        printf("File already exists.\n");
    }
    if (strcmp(message, full) == 0) {
        printf("Can't upload more files. Limit reached.\n");
    }
    if (strcmp(message, nok) == 0) {
        printf("Upload failed.\n");
    }
    close(fd_fs);
    free(message);
    return;
}

void delete(char* input, int index) {

    if (!logged_in || request->uid == NULL || request->tid == NULL || request->fname == NULL) return;

    int input_index = index;
    char ok[9] = "RDL OK\n\0";

    char* filename = split(input, &input_index, '\n', FILE_NAME_SIZE + 1);
    if (filename == NULL || validate_filename(filename) == -1 || strcmp(filename, request->fname) != 0) {
        printf("Invalid filename.\n");
        free(filename);
        return;
    }

    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (sprintf(message, "DEL %s %s %s\n", request->uid, request->tid, filename) < 0) {
        free(message);
        free(filename);
        printf("sprintf error\n");
        return;
    }
    free(filename);

    fd_fs = connect_tcp(fs_ip, fs_port);

    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    int n = write(fd_fs, message, strlen(message));
    if(n == -1) {
        printf("Delete failed.\n");
        free(message);
        return;
    }

    message[0] = '\0';

    n = read(fd_fs, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return; 
    }
    message[n] = 0;
    if (strcmp(message, ok) == 0) {
        printf("Delete successful.\n");
    }else{
        printf("Delete failed.\n");
    }
    free(message);
    close(fd_fs);
    return;
}

void remove_all() {

    if (!logged_in || request->uid == NULL || request->tid == NULL) return;

    char ok[9] = "RRM OK\n\0";

    char* message = (char*) malloc(sizeof(char) * BUFFER_SIZE);

    if (sprintf(message, "REM %s %s\n", request->uid, request->tid) < 0) {
        free(message);
        printf("sprintf error\n");
        return;
    }

    fd_fs = connect_tcp(fs_ip, fs_port);
    if (fd_fs == -1) {
        printf("can't create socket\n");
        free(fs_port);
        exit(EXIT_FAILURE);
    }

    int n = write(fd_fs, message, strlen(message));
    if(n == -1) {
        printf("Remove failed.\n");
        return;
    }

    message[0] = '\0';

    n = read(fd_fs, message, BUFFER_SIZE);
    if (n == -1) {
        free(message);
        printf("can't read message from fs\n");
        return; 
    }
    message[n] = 0;

    if (strcmp(message, ok) == 0) {
        printf("Remove successful.\n");
    }else{
        printf("Remove failed.\n");
    }
    free(message);
    close(fd_fs);
    return;
}

void disconnect_user() {
    running = FALSE;
}

void treat_command(char* input) {
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
            return;
        }
    }

    input_index = 0;
    char login_str[6] = "login\0";
    aux = split(input, &input_index, ' ', 6);
    if (aux == NULL)
        free(aux);
    else {
        if (strcmp(aux, login_str) != 0)
            free(aux);
        else {
            login(input, input_index);
            free(aux);
            return;
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
            request_operation(input, input_index);
            free(aux);
            return;
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
            validate_operation(input, input_index);
            free(aux);
            return;
        }
    }   
    
    input_index = 0;
    char list_str[5] = "list\0", l[2] = "l\0";
    aux = split(input, &input_index, '\n', 5);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, list_str) != 0) && (strcmp(aux, l) != 0))
            free(aux);
        else {
            list();
            free(aux);
            return;
        } 
    }  
    
    input_index = 0;
    char retrieve_str[9] = "retrieve\0";
    char r[2] = "r\0";
    aux = split(input, &input_index, ' ', 9);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, retrieve_str) != 0) && (strcmp(aux, r) != 0))
            free(aux);
        else {
            free(aux);
            retrieve(input, input_index);
            return;
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
            upload(input, input_index);
            free(aux);
            return;
        }
    }  
    
    input_index = 0;
    char delete_str[7] = "delete\0", d[2] = "d\0";
    aux = split(input, &input_index, ' ', 7);
    if (aux == NULL)
        free(aux);
    else {
        if ((strcmp(aux, delete_str) != 0) && (strcmp(aux, d) != 0))
            free(aux);
        else {
            delete(input, input_index);
            free(aux);
            return;
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
            remove_all();
            free(aux);
            return;
        }
    }
    printf("Invalid Command\n");
    return;
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
                exit(EXIT_FAILURE);
            default:
                if(FD_ISSET(0, &testfds)) {
                    if (( n = read(0, in_str, BUFFER_SIZE))!= 0) {
                        if (n == -1) {
                            printf("cant read from stdin\n");
                            exit(1); 
                        } 
                        in_str[n]=0;
                        treat_command(in_str);
                    }
                }
                break;  
        }
    }

    close(fd_as);
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

