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
#include <dirent.h>
#define MAX_REQUESTS 20

char default_tid[5] = "0000\n";

int no_requests = 0;
int user_been_treat = -1;
int users_login_info[MAX_USERS];

typedef struct request {
    char uid[6];
    char rid[5];
    char vc[5];
    char tid[5];
    char fop[2];
    char* fname;
} Request;

Request* users_requests[MAX_REQUESTS];

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

int validate_four_digit_number(char* num) {
    if (strlen(num) != 4) return -1;
    else if (num[0] == '0') return -1;

    for (int i = 1; i < 4; i++) {
        if (num[i] < '0' || num[i] > '9') return -1;
    }

    return 0;
}

int validate_fop(char* fop) {
    int i = -1;
    if (strlen(fop) != 1) return -1;

    if (strcmp(fop, "L") == 0 || strcmp(fop, "X") == 0)
        i = 1;
    if (strcmp(fop, "R") == 0 || strcmp(fop, "U") == 0 || strcmp(fop, "D") == 0)
        i = 2;
    
    return i;
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

    int i = (int) strlen(input);
    if (*index >= i)
        return NULL;

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

int equal_passwords(char* u_ist_id, char* password) {
    char pass_path_file[28];
    FILE* pass_file;
    char p[9];
    sprintf(pass_path_file, "USERS/%s/%s_pass.txt", u_ist_id, u_ist_id);
    pass_file = fopen(pass_path_file, "r");
    fscanf(pass_file, "%s", p);
    fclose(pass_file);
    //pass diferente
    if (strcmp(password, p) != 0)
        return FALSE;
    //pass igual
    else 
       return TRUE;
        
}

int UID_exists(char* u_ist_id) {
    DIR* d;
    char dirname[28];

    sprintf(dirname, "USERS/%s", u_ist_id);
    d = opendir(dirname);
    if (d) {
        closedir(d);
        return TRUE;
    }
    return FALSE;
}

int check_rid_exists(char* rid, char* u_ist_id) {
    for (int i = 0; i < no_requests; i++) {
        if (strcmp(users_requests[i]->uid, u_ist_id) == 0)
            if (strcmp(users_requests[i]->rid, rid) == 0)
                return TRUE;
    }
    return FALSE;
}

int get_request_index(char* n_id, char* u_ist_id, int option) {
    //se option for 0, entao quer usar o rid, se for 1 quer usar o tid
    for (int i = 0; i < no_requests; i++) {
        if (strcmp(users_requests[i]->uid, u_ist_id) == 0)
            if (option == 0) {
                if (strcmp(users_requests[i]->rid, n_id) == 0)
                    return i;
            }
            if (option == 1) {
                if (strcmp(users_requests[i]->tid, n_id) == 0)
                    return i;
            }
    }
    return -1;
}

int four_digit_number_generator() {
    return rand() % 9000 + 1000;
}

int user_logged_with_uid(char* u_ist_id) {
    FILE* uid_login_file;
    char login_filename[28];
    char user_number[3];
    sprintf(login_filename, "USERS/%s/%s_login.txt", u_ist_id, u_ist_id);
    if (access(login_filename, F_OK) != -1) {
        uid_login_file = fopen(login_filename, "r");
        fscanf(uid_login_file, "%s", user_number);
        fclose(uid_login_file);
    }
    //caso o ficheiro de log in nao exista por nenhum user ter efetuado login com este uid
    else {
       sprintf(user_number, "%d", -1); 
    }
    return atoi(user_number);
}

char* regist_UID(char* message, int i) {  
    int input_index = i;
    char ok[9] = "RRG OK\n\0";
    char nok[9] = "RRG NOK\n\0";
    char* reg_status = (char*) malloc(sizeof(char) * 9);
    strcpy(reg_status, nok);
    
    char* u_ist_id = split(message, &input_index, ' ', 6);
    if (u_ist_id == NULL) {
        free(u_ist_id);
        return reg_status;   
    }
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        return reg_status;
    }
    
    char* password = split(message, &input_index, ' ', 9);
    if (password == NULL) {
        free(u_ist_id);
        free(password);
        return reg_status; 
    }
    if (validate_password(password) != 0) {
        free(u_ist_id);
        free(password);
        return reg_status;
    }
    
    char* pd_ip = split(message, &input_index, ' ', 16);
    if (pd_ip == NULL) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        return reg_status; 
    }
    if (validate_ip(pd_ip) != 0) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        return reg_status;
    }

    char* pd_port = split(message, &input_index, '\n', 6);
    if (pd_port == NULL) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        return reg_status;    
    }
    if (validate_port(pd_port) != 0) {
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        return reg_status;
    }

    //se ja existir este id, verifica se password é igual, se for, escreve o ip e porto e retorna OK, se nao for NOK
    char v = UID_exists(u_ist_id);
    if (v) {
        if (equal_passwords(u_ist_id, password)) {
            strcpy(reg_status, ok);
            FILE* uid_reg_file;
            char reg_filename[28];
            sprintf(reg_filename, "USERS/%s/%s_reg.txt", u_ist_id, u_ist_id);
            uid_reg_file = fopen(reg_filename, "w");
            fprintf(uid_reg_file, "%s %s\n", pd_ip, pd_port);
            fclose(uid_reg_file);
        }
        else
            strcpy(reg_status, nok);

        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        return reg_status;
    }
    else {
        struct stat st = {0};

        char dir[13];
        sprintf(dir, "USERS/%s", u_ist_id);

        if (stat(dir, &st) == -1) {
            mkdir(dir, 0700);
        }

        FILE* uid_pass_file;
        FILE* uid_reg_file;

        char pass_filename[28];
        char reg_filename[28];

        sprintf(pass_filename, "USERS/%s/%s_pass.txt", u_ist_id, u_ist_id);
        sprintf(reg_filename, "USERS/%s/%s_reg.txt", u_ist_id, u_ist_id);

        uid_pass_file = fopen(pass_filename, "w");
        uid_reg_file = fopen(reg_filename, "w");

        if (uid_pass_file == NULL || uid_reg_file == NULL) {      
            printf("Unable to create file.\n");
            exit(EXIT_FAILURE);
        }

        fprintf(uid_pass_file, "%s\n", password);
        fprintf(uid_reg_file, "%s %s\n", pd_ip, pd_port);

        fclose(uid_pass_file);
        fclose(uid_reg_file);

    
        free(u_ist_id);
        free(password);
        free(pd_ip);
        free(pd_port);
        strcpy(reg_status, ok);
        return reg_status;
    }
}

char* login_UID(char* message, int i) {
    int input_index = i;
    char ok[9] = "RLO OK\n\0"; // pass e id corretos
    char nok[9] = "RLO NOK\n\0";    //pass incorreta, id existente
    char err[9] = "RLO ERR\n\0";    //id inexistente
    char* log_status = (char*) malloc(sizeof(char) * 9);
    strcpy(log_status, err);

    char* u_ist_id = split(message, &input_index, ' ', 6);
    if (u_ist_id == NULL) {
        free(u_ist_id);
        return log_status;     
    }
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        return log_status;
    }

    char* password = split(message, &input_index, '\n', 9);
    if (password == NULL) {
        free(u_ist_id);
        free(password);
        return log_status;    
    }
    if (validate_password(password) != 0) {
        free(u_ist_id);
        free(password);
        return log_status;
    }

    int v = UID_exists(u_ist_id);
    if (!v){
        free(u_ist_id);
        free(password);
        return log_status;
    }
    else {
        if (equal_passwords(u_ist_id, password)) {
            strcpy(log_status, ok);
            FILE* uid_login_file;
            char login_filename[28];
            sprintf(login_filename, "USERS/%s/%s_login.txt", u_ist_id, u_ist_id);
            uid_login_file = fopen(login_filename, "w");
            fprintf(uid_login_file, "%d\n", user_been_treat);
            fclose(uid_login_file);
            users_login_info[user_been_treat] = 1; // significa que este user efetuou um login com um UID
        }
        else
            strcpy(log_status, nok);        
        
        return log_status;
    }

}

char* request_VC(char* message, int i) {
    int input_index = i;
    char ok[9] = "RRQ OK\n\0"; // deu ok
    char nok[5] = "NOK\n\0";
    char elog[10] = "RRQ ELOG\n\0"; // o user nao efetuou login, nao foi estabelecida uma sessao tcp
    char epd[9] = "RRQ EPD\n\0";  //message not be sent by as to the pd
    char euser[11] = "RRQ EUSER\n\0"; // uid is incorrect
    char efop[10] = "RRQ EFOP\n\0"; //invalid Fop
    char err[9] = "RLO ERR\n\0";    //REQ message incorrectly formatted
    char* rrq_status = (char*) malloc(sizeof(char) * 11);
    
    char* u_ist_id = split(message, &input_index, ' ', 6); 
    if (u_ist_id == NULL) {
        free(u_ist_id);
        strcpy(rrq_status, euser);
        return rrq_status;
    }
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        strcpy(rrq_status, euser);
        return rrq_status;
    }
    //verifica se o user efetuou login com algum UID
    if (users_login_info[user_been_treat] == 0) {
        free(u_ist_id);
        strcpy(rrq_status, elog);
        return rrq_status;
    }

    //verifica se o user efetuou REQ com um UID existente
    int v = UID_exists(u_ist_id);

    if(!v) {
        strcpy(rrq_status, euser);
        free(u_ist_id);
        return rrq_status;
    }

    //verifica se o user efetuou Req com o uid que efetuou login
    int u = user_logged_with_uid(u_ist_id);
    //user nao efetuou REQ para o seu UID com que efetuou login
    if (u != user_been_treat) {
        free(u_ist_id);
        strcpy(rrq_status, euser);
        return rrq_status;
    }

    //leitura e verificacao do RID
    char* rid = split(message, &input_index, ' ', 5);
    if (rid == NULL) {
        strcpy(rrq_status, err);
        free(u_ist_id);
        free(rid);
        return rrq_status;
    }
    if (validate_four_digit_number(rid) != 0) {
        strcpy(rrq_status, err);
        free(u_ist_id);
        free(rid);
        return rrq_status;
    }
    //se o rid ja existir para o mesmo UID
    if (check_rid_exists(rid, u_ist_id)) {
        strcpy(rrq_status, err);
        free(u_ist_id);
        free(rid);
        return rrq_status;    
    }

    //leitura e verificacao de FOP

    char* fop = split(message, &input_index, ' ', 2);

    if (fop == NULL) {
        strcpy(rrq_status, efop);
        free(u_ist_id);
        free(rid);
        free(fop);
        return rrq_status;
    }
    int f = validate_fop(fop);
    if (f == -1) {
        strcpy(rrq_status, efop);
        free(u_ist_id);
        free(rid);
        free(fop);
        return rrq_status;
    }

    //leitura de Fname
    char* fname = split(message, &input_index, '\n', FILE_NAME_SIZE);

    if (f == 2) {
        if (fname == NULL) {
            free(u_ist_id);
            free(rid);
            free(fop);
            free(fname);
            strcpy(rrq_status, err);
            return rrq_status;    
        }
    }
    else {
        if (fname != NULL) {
            free(u_ist_id);
            free(rid);
            free(fop);
            free(fname);
            strcpy(rrq_status, err);
            return rrq_status;
        }    
    }

    //criacao da mensagem VLC do as para o pd
    char vlc_message_to_pd[45];
    int vc = four_digit_number_generator();
    if (f == 2)
        sprintf(vlc_message_to_pd, "VLC %s %d %s %s\n", u_ist_id, vc, fop, fname);    
    else
        sprintf(vlc_message_to_pd, "VLC %s %d %s\n", u_ist_id, vc, fop);

    no_requests++;
    Request *request = (Request*) malloc(sizeof(Request));
    char vc_str[5];
    sprintf(vc_str, "%d", vc);
    strcpy(request->uid, u_ist_id);
    strcpy(request->rid, rid);
    strcpy(request->vc, vc_str);
    strcpy(request->fop, fop);
    strcpy(request->tid, default_tid);
    if (f == 2) {
        request->fname = (char*) malloc(sizeof(char) * (strlen(fname) + 1));
        strcpy(request->fname, fname);
    }
    users_requests[no_requests-1] = request; 

    free(rid);
    free(fop);

    //leitura do pd ip e pd port do ficheiro de registo txt
    FILE* uid_reg_file;

    char reg_filename[28];
    sprintf(reg_filename, "USERS/%s/%s_reg.txt", u_ist_id, u_ist_id);
    uid_reg_file = fopen(reg_filename, "r");
    char pd_ip[16];
    char pd_port[6];
    fscanf(uid_reg_file, "%s %s", pd_ip, pd_port);

    char* rvc_status = send_udp(vlc_message_to_pd, pd_ip, pd_port);

    //verificacao do rvc status
    int index = 0;
    char* rvc = split(rvc_status, &index, ' ', 4);
    char* uid = split(rvc_status, &index, ' ', 6);
    char* status = split(rvc_status, &index, ' ', 4);
    char r[4] = "RVC\0";

    free(rvc_status);
    //verifica se o rvc status é do tipo "RVC UID"
    if (strcmp(rvc, r) != 0 || strcmp(uid, u_ist_id) != 0){
        strcpy(rrq_status, epd);
        free(u_ist_id);
        free(rvc);
        free(uid);
        free(status);
        return rrq_status;
    }
    if (strcmp(status, nok) == 0)
        strcpy(rrq_status, err);
    else
        strcpy(rrq_status, ok);

    free(u_ist_id);
    free(rvc);
    free(uid);
    free(status);
    return rrq_status;
}

char* check_VC(char* message, int i) {
    int input_index = i;
    char failed[7] = "RAU 0\n\0";
    char* rau_status = (char*) malloc(sizeof(char)*10);
    strcpy(rau_status, failed);

    char* u_ist_id = split(message, &input_index, ' ', 6); 
    if (u_ist_id == NULL) {
        free(u_ist_id);
        return rau_status;
    }
    if (validate_u_ist_id(u_ist_id) != 0) {
        free(u_ist_id);
        return rau_status;
    }

    //verifica se o user efetuou login com algum UID
    if (users_login_info[user_been_treat] == 0) {
        free(u_ist_id);
        return rau_status;
    }

    //verifica se o user efetuou AUT com um UID existente
    int v = UID_exists(u_ist_id);

    if(!v) {
        free(u_ist_id);
        return rau_status;
    }

    //verifica se o user efetuou AUT com o uid que efetuou login
    int u = user_logged_with_uid(u_ist_id);
    //user nao efetuou AUT para o seu UID com que efetuou login
    if (u != user_been_treat) {
        free(u_ist_id);
        return rau_status;
    }

    //leitura e verificacao do RID
    char* rid = split(message, &input_index, ' ', 5);
    if (rid == NULL) {
        free(u_ist_id);
        free(rid);
        return rau_status;
    }
    if (validate_four_digit_number(rid) != 0) {
        free(u_ist_id);
        free(rid);
        return rau_status;
    }
    //verifica se o RID existe para o UID e se nao exitir RID entao devolve RAU 0, como em todos os outros casos de erro nesta funcao
    if (!check_rid_exists(rid, u_ist_id)) {
        free(u_ist_id);
        free(rid);
        return rau_status;    
    }

    char* vc = split(message, &input_index, '\n', 5);
    if(validate_four_digit_number(vc) != 0) {
        free(u_ist_id);
        free(rid);
        free(vc);
        return rau_status;
    }

    int request_index = get_request_index(rid, u_ist_id, 0);
    if (strcmp(users_requests[request_index]->vc, vc) == 0) {
        //verifica se o tid ja foi criado
        if (strcmp(users_requests[request_index]->tid, default_tid) == 0) {
            int tid = four_digit_number_generator();
            char tid_str[5];
            sprintf(tid_str, "%d", tid);
            sprintf(rau_status, "RAU %s\n", tid_str);
            strcpy(users_requests[request_index]->tid, tid_str);
        }
        //caso ja tenha um tid mantem se o mesmo nao se altera
        else {
            sprintf(rau_status, "RAU %s\n", users_requests[request_index]->tid);   
        }
        
    }
        
    free(u_ist_id);
    free(rid);
    free(vc);
    return rau_status;
}

char* vld_operation(char* message, int i) {
    int input_index = i;
    
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
        char* answer = regist_UID(message, input_index);
        free(action);
        return answer;
        //trata de verificar o REG
    }

    char log[4] = "LOG\0";
    if (strcmp(action, log) == 0) {
        char* answer = login_UID(message, input_index);
        free(action);
        return answer;
        //trata de fazer o Login
    }

    char req[4] = "REQ\0";
    if (strcmp(action, req) == 0) {
        char* answer = request_VC(message, input_index);
        free(action);
        return answer;
        //trata a operacao req
    }

    char aut[4] = "AUT\0";
    if (strcmp(action, aut) == 0) {
        char* answer = check_VC(message, input_index);
        free(action);
        return answer;
        //trata a operacao aut
    }

    char vld[4] = "VLD\0";
    if (strcmp(action, vld) == 0) {
        char* answer = vld_operation(message, input_index);
        free(action);
        return answer;
        //trata a operacao vld
    }

    //nenhuma operacao valida
    char err[4] = "ERR\0";
    char* answer = (char*) malloc(sizeof(char) * 4);
    strcpy(answer, err);
    return answer;
}

int main(int argc, char **argv) {

    if (argc < 1 || argc > 4) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < MAX_USERS; i++)
        users_login_info[i] = 0; //coloca todas as posicoes a 0 para informar que os users que se podem ligar ao as nao efetuaram login, se efetuarem um login bem sucedido entao é colocado a 1 na sua posicao
        
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
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    char* in_str = (char*) malloc(sizeof(char) * BUFFER_SIZE);
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
                    printf("read udp\n");
                    struct sockaddr_in addr;
                    socklen_t addrlen = sizeof(addr);
                    ssize_t n;
                    n = recvfrom (fd_pd, in_str, BUFFER_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
                    if (n == -1) /*error*/ break;    
                    char* answer = treatMessage(in_str);
                    n = sendto (fd_pd, answer, strlen(answer), 0, (struct sockaddr*)&addr, addrlen);
                    if (n == -1) /*error*/break;
                }
                if (FD_ISSET(fd_user, &testfds)) {
                    printf("read tcp\n");
                    int newfd;
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
                        user_been_treat = i;
                        n = read (users[i], in_str, BUFFER_SIZE - 1);
                        in_str[n] = 0;
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
  /*  for (int i = 0; i < no_UIDs; i++) {
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