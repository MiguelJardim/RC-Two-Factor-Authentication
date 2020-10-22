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
#include "../aux/constants.h"


int no_users = 0;

FILE* uids;

int validate_port(char* port) {
    if (strlen(port) != 5) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
}

int validate_u_ist_id(char* uid) {
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

    while (c != separator && c != EOF && c != '\n') {
        if (output_index == size - 1)  {
            free(output);
            return NULL;
        }
        output[output_index++] = c;
        c = input[(*index)++];
    }

    output[output_index] = '\0';

    return output;
}

int user_exists(char* u_ist_id, char* password) {
    for (int i = 1; i <= no_users; i++) {
        FILE* uid_file;
        char uid_path_file[28];
        sprintf(uid_path_file, "USERS/UID%d/UID%d_uid.txt", i, i);
        uid_file = fopen(uid_path_file, "r");
        char uid[6];
        fscanf(uid_file, "%s", uid);
        fclose(uid_file);
        if (strcmp(uid, u_ist_id) == 0) {
            char pass_path_file[28];
            FILE* pass_file;
            char p[9];
            sprintf(pass_path_file, "USERS/UID%d/UID%d_pass.txt", i, i);
            pass_file = fopen(pass_path_file, "r");
            fscanf(pass_file, "%s", p);
            fclose(pass_file);
            //existe e pass diferente
            if (strcmp(password, p) != 0) {
                return -1;
            }
            //existe e pass igual
            else {
                return i;
            }
        }
    }
    //nao existe
    return -2;
}

char* registUser(char* message, int i) {  
    int input_index = i;
    char ok[9] = "RRG OK\n\0";
    char nok[9] = "RRG NOK\n\0";
    char* reg_status = (char*) malloc(sizeof(char) * 9);
    strcpy(reg_status, nok);
    
    char* u_ist_id = split(message, &input_index, ' ', 6);
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        return reg_status;
    }
    
    char* password = split(message, &input_index, ' ', 9);
    if (validate_password(password) != 0) {
        free(u_ist_id);
        free(password);
        return reg_status;
    }
    
    char* pd_ip = split(message, &input_index, ' ', 16);
    if (validate_ip(pd_ip) != 0) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        return reg_status;
    }

    char* pd_port = split(message, &input_index, ' ', 6);
    if (validate_port(pd_port) != 0) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        return reg_status;
    }

    //se ja existir este id, verifica se password é igual, se for OK, se nao for NOK
    char v = user_exists(u_ist_id, password);
    if (v == 0) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        strcpy(reg_status, ok);
        return reg_status;
    }
    else if (v == -1) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        return reg_status;
    }
    else {
        struct stat st = {0};
    
        no_users++;

        char dir[13];
        sprintf(dir, "USERS/UID%d", no_users);

        if (stat(dir, &st) == -1) {
            mkdir(dir, 0700);
        }

        FILE* uid_pass_file;
        FILE* uid_reg_file;
        FILE* uid_file;

        char pass_filename[28];
        char reg_filename[28];
        char uid_filename[28];

        sprintf(pass_filename, "USERS/UID%d/UID%d_pass.txt", no_users, no_users);
        sprintf(reg_filename, "USERS/UID%d/UID%d_reg.txt", no_users, no_users);
        sprintf(uid_filename, "USERS/UID%d/UID%d_uid.txt", no_users, no_users);

        uid_pass_file = fopen(pass_filename, "w");
        uid_reg_file = fopen(reg_filename, "w");
        uid_file = fopen(uid_filename, "w");

        if (uid_pass_file == NULL || uid_reg_file == NULL || uid_file == NULL) {      
            printf("Unable to create file.\n");
            exit(EXIT_FAILURE);
        }

        fprintf(uid_pass_file, "%s\n", password);
        fprintf(uid_reg_file, "%s %s\n", pd_ip, pd_port);
        fprintf(uid_file, "%s\n", u_ist_id);

        fclose(uid_pass_file);
        fclose(uid_reg_file);
        fclose(uid_file);

    
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        strcpy(reg_status, ok);
        return reg_status;
    }
}

char* loginUser(char* message, int i) {
    int input_index = i;
    char ok[9] = "RLO OK\n\0"; // pass e id corretos
    char nok[9] = "RLO NOK\n\0";    //pass incorreta, id existente
    char err[9] = "RLO ERR\n\0";    //id inexistente
    char* log_status = (char*) malloc(sizeof(char) * 9);
    strcpy(log_status, nok);

    char* u_ist_id = split(message, &input_index, ' ', 6);
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        return log_status;
    }

    char* password = split(message, &input_index, ' ', 9);
    if (validate_password(password) != 0) {
        free(u_ist_id);
        free(password);
        return log_status;
    }

    int v = user_exists(u_ist_id, password);
    if (v == -1) {
        free(u_ist_id);
        free(password);
        return log_status;
    }
    else if (v == -2){
        free(u_ist_id);
        free(password);
        strcpy(log_status, err);
        return log_status;
    }
    else {
        free(u_ist_id);
        free(password);
        strcpy(log_status, ok);
        FILE* uid_login_file;
        char login_filename[28];
        sprintf(login_filename, "USERS/UID%d/UID%d_login.txt", v, v);
        uid_login_file = fopen(login_filename, "w");
        char t[6] = "true\0";
        fprintf(uid_login_file, "%s\n", &t);
        fclose(uid_login_file);
        return log_status;
    }

}

/*char* requestVC(char* message, int i) {
    int input_index = i;
    
    
    char* u_ist_id = split(message, &input_index, ' ', 6);
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        return rrq_status;
    }
}*/

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

int open_tcp(char* port) {
    int fd, errcode;
    ssize_t n;
    struct addrinfo hints,*res;
    

    fd = socket(AF_INET,SOCK_STREAM,0);
    if (fd == -1) exit(1); //error

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, port, &hints, &res);
    if((errcode) != 0) /*error*/ exit(1);

    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if(n == -1) /*error*/ exit(1);

    if(listen(fd, 5) == -1) /*error*/ exit(1);

    freeaddrinfo(res);
    return fd;
}

char* treatMessage(char* message) {
    int input_index = 0;

    char* action = split(message, &input_index, ' ', 4);
    
    char reg[4] = "REG\0";
    if (strcmp(action, reg) == 0) {
        char* answer = registUser(message, input_index);
        free(action);
        return answer;
        //trata de verificar o REG
    }

    char log[4] = "LOG\0";
    if (strcmp(action, log) == 0) {
        char* answer = loginUser(message, input_index);
        free(action);
        return answer;
        //trata de fazer o Login
    }

    char req[4] = "REQ\0";
    if (strcmp(action, req) == 0) {
   //     char* answer = requestVC(message, input_index);
        free(action);
     //   return answer;
        //trata a operacao req
    }

    char aut[4] = "AUT\0";
    if (strcmp(action, aut) == 0) {
        free(action);
        //trata a operacao aut
    }

    char vld[4] = "VLD\0";
    if (strcmp(action, vld) == 0) {
        free(action);
        //trata a operacao vld
    }

    //nenhuma operacao valida
    char err[4] = "ERR\0";
    char* answer = (char*) malloc(sizeof(char) * 4);
    strcpy(answer, err);
    return answer;
}

char* send_udp(char* message, char* ip, char* port) {
    int fd,errcode;
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

    errcode = getaddrinfo(ip, port, &hints, &res) ;
    if(errcode!=0)  exit(1);

    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if(n==-1) exit(1);

    addrlen = sizeof(addr);
    n = recvfrom (fd, buffer, 128,0, (struct sockaddr*)&addr, &addrlen);
    if(n == -1) exit(1);

    freeaddrinfo(res);
    close (fd);

    return buffer;
}

int open_udp(char* port) {
    int fd,errcode;
    ssize_t n;
    struct addrinfo hints,*res;
    
    fd=socket(AF_INET,SOCK_DGRAM,0);
    if(fd==-1) /*error*/exit(1);

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; // IPv4
    hints.ai_socktype=SOCK_DGRAM; // UDP socket
    hints.ai_flags=AI_PASSIVE;

    errcode= getaddrinfo (NULL,port,&hints,&res);
    if(errcode!=0) /*error*/ exit(1);

    n= bind (fd,res->ai_addr, res->ai_addrlen);
    if(n==-1) /*error*/ exit(1);

    freeaddrinfo(res);
    
    return fd;

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

    //new directory USERS
    struct stat st = {0};
    if (stat("USERS", &st) == -1) {
        mkdir("USERS", 0700);
    }

    int* users = (int*) malloc(sizeof(int) * MAX_USERS);
    for (int i = 0; i < MAX_USERS; i++) {
        users[i] = -1;
    }

    int fd_pd = open_udp(as_port);
    int fd_user = open_tcp(as_port);
    char* in_str = (char*) malloc(sizeof(char) * 128);
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    FD_ZERO(&inputs); 
    FD_SET(fd_pd, &inputs);
    FD_SET(fd_user, &inputs);
    while(TRUE) {
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
                if (FD_ISSET(fd_pd, &testfds)) {
                    printf("read upd\n");
                    struct sockaddr_in addr;
                    socklen_t addrlen = sizeof(addr);
                    ssize_t n;
                    n = recvfrom (fd_pd, in_str, 128, 0, (struct sockaddr*)&addr, &addrlen);
                    if (n == -1) /*error*/ break;    
                    char* answer = treatMessage(in_str);  
                    n = sendto (fd_pd, answer, strlen(answer), 0, (struct sockaddr*)&addr, addrlen);
                    if (n == -1) /*error*/break;
                }
                if (FD_ISSET(fd_user, &testfds)) {
                    printf("read tcp\n");
                    int newfd;
                    ssize_t n;
                    struct sockaddr_in addr;
                    socklen_t addrlen;
                    addrlen = sizeof(addr);
                    if ((newfd = accept(fd_user, (struct sockaddr*)&addr, &addrlen)) == -1 ) /*error*/ exit(1);
                    for (int i = 0; i < MAX_USERS; i++) {
                        if (users[i] == -1) {
                            printf("added user\n");
                            users[i] = newfd;
                            FD_SET(users[i], &inputs);
                            break;
                        }
                    }
                }
                for (int i = 0; i < MAX_USERS; i++) {
                    if (users[i] != -1 && FD_ISSET(users[i], &testfds)) {
                        n = read (users[i], in_str, BUFFER_SIZE);
                        if(n == -1) exit(EXIT_FAILURE);
                        char* answer = treatMessage(in_str);
                        n = write (users[i], answer, n);
                        if (n == -1)  exit(1);
                    }
                }
                break;
        }
    }

//apaga os ficheiros e diretorios, esta comentado só para conseguir ver se esta a criar bem os diretorios, na versao final vai estar a funcionar
  /*  for (int i = 0; i < no_users; i++) {
        char aux[28];
        sprintf(aux, "USERS/UID%d/UID%d_pass.txt", i + 1, i + 1);
        remove(aux);
        sprintf(aux, "USERS/UID%d/UID%d_reg.txt", i + 1, i + 1);
        remove(aux);
        sprintf(aux, "USERS/UID%d", i + 1);
        rmdir(aux);
    }

    if (stat("USERS", &st) == 0) {
        rmdir("USERS");
    }
    */

    return 0;



}