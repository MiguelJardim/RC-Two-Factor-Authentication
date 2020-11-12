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

#define MAX_REQUESTS 20

int socket_closed = FALSE;
int verbose = FALSE;
int no_requests = 0;
int user_been_treat = -1;
int users_login_info[MAX_USERS];
int running = TRUE;

typedef struct request {
    char *uid;
    char *rid;
    char *vc;
    char *tid;
    char *fop;
    char* fname;
} Request;

Request** users_requests;

Request* new_request(char* uid, char* rid, char* vc, char* fop) {
    Request *request = (Request*) malloc(sizeof(Request));

    request->uid = (char*) malloc(sizeof(char) * (UID_SIZE + 1));
    request->rid = (char*) malloc(sizeof(char) * (TID_SIZE + 1));
    request->vc = (char*) malloc(sizeof(char) * (TID_SIZE + 1));
    request->fop = (char*) malloc(sizeof(char) * 2);
    
    strcpy(request->uid, uid);
    strcpy(request->rid, rid);
    strcpy(request->vc, vc);
    strcpy(request->fop, fop);
    request->tid = NULL;
    request->fname = NULL;

    return request;
} 

void update_request(Request* request, char* rid, char* vc, char* fop, char* fname) {
    
    strcpy(request->rid, rid);
    strcpy(request->vc, vc);
    strcpy(request->fop, fop);
    if (request->tid != NULL) {
        free(request->tid);
        request->tid = NULL;
    }
    if (request->fname == NULL && fname != NULL) {
        request->fname = (char*) malloc(sizeof(char) * (strlen(fname) + 1));
        strcpy(request->fname, fname);
    }
    else if (request->fname != NULL && fname != NULL) {
        free(request->fname);
        request->fname = (char*) malloc(sizeof(char) * (strlen(fname) + 1));
        strcpy(request->fname, fname);
    }
    else if (request->fname != NULL && fname == NULL) {
        free(request->fname);
        request->fname = NULL;
    }
    
}

char* split_message(char* input, int* index, char separator, int size) {
    char* output = (char*) malloc(sizeof(char) * size);
    int output_index = 0;

    if (input == NULL) {
        free(output);
        return NULL;
    }

    int i = (int) strlen(input);
    if (*index >= i) {
        free(output);
        return NULL;
    }
        

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
    if (pass_file == NULL) {      
        if (verbose) printf("Unable to open password file.\n");
        return FALSE;
    }
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
    char dirname[13];
    char reg_filename[28];
    sprintf(dirname, "USERS/%s", u_ist_id);
    sprintf(reg_filename, "USERS/%s/%s_reg.txt", u_ist_id, u_ist_id);
    d = opendir(dirname);
    if (d) {
        if (access(reg_filename, F_OK) != -1) {
            closedir(d);
            return TRUE;
        }
        else {
            closedir(d);
            return FALSE;  
        }
        
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

int tid_exists_for_uid(char* u_ist_id, char* tid) {
    
    for (int i = 0; i < no_requests; i++) {
        if (strcmp(users_requests[i]->uid, u_ist_id) == 0) {
            if (users_requests[i]->tid != NULL && strcmp(users_requests[i]->tid, tid) == 0)
                return i;
        }
    }
    return -1;
}

int get_request_index(char* n_id, char* u_ist_id, int option) {
    //se option for 0, entao quer usar o rid, se for 1 quer usar o tid
    for (int i = 0; i < no_requests; i++) {
        if (strcmp(users_requests[i]->uid, u_ist_id) == 0) {
            if (option == 0) {
                if (strcmp(users_requests[i]->rid, n_id) == 0)
                    return i;
            }
            else if (option == 1) {
                if (strcmp(users_requests[i]->tid, n_id) == 0)
                    return i;
            }
            else if (option == 2) {
                return i;
            }
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
        if (uid_login_file == NULL) {      
            if (verbose) printf("Unable to open login file.\n");
            return -1;
        }
        fscanf(uid_login_file, "%s", user_number);
        fclose(uid_login_file);
    }
    //caso o ficheiro de log in nao exista por nenhum user ter efetuado login com este uid
    else {
       return -1;
    }
    return atoi(user_number);
}

void logout_user(char* u_ist_id) {
    FILE* uid_login_file;
    char login_filename[28];
    char user_number[3];
    sprintf(login_filename, "USERS/%s/%s_login.txt", u_ist_id, u_ist_id);
    if (access(login_filename, F_OK) != -1) {
        //se o ficheiro existe
        uid_login_file = fopen(login_filename, "r");
        if (uid_login_file == NULL) {      
            if (verbose) printf("Unable to open login file\n");
            return;
        }
        fscanf(uid_login_file, "%s", user_number);
        fclose(uid_login_file);
        if (remove(login_filename) != 0) {
            if (verbose) printf("Unable to delete login file and logout user\n");
            return;
        }   
    }
    else
        return;
    
    users_login_info[atoi(user_number)] = -1;
    return;
}

void disconnect_user() {
    if (users_login_info[user_been_treat] == -1)    return;

    char login_filename[28];
    sprintf(login_filename, "USERS/%d/%d_login.txt", users_login_info[user_been_treat], users_login_info[user_been_treat]);
    if (access(login_filename, F_OK) != -1) {
        if (remove(login_filename) != 0) {
            if (verbose) printf("Unable to delete login file and logout user\n");
            return;
        }   
    }
    else {
        users_login_info[user_been_treat] = -1;
        return;
    }

    users_login_info[user_been_treat] = -1;
    return;
}

void delete_uid_files(char* u_ist_id) {
    char reg_filename[28], pass_filename[28];
    sprintf(reg_filename, "USERS/%s/%s_reg.txt", u_ist_id, u_ist_id);
    sprintf(pass_filename, "USERS/%s/%s_pass.txt", u_ist_id, u_ist_id);
    if (access(reg_filename, F_OK) != -1) {
        if (remove(reg_filename) != 0) {
            if (verbose) printf("Unable to delete reg file and unregist UID\n");
            return;
        }      
    }
    else {
        if (verbose) printf("inexistent file\n");
        return;
    }
        
    
    if (access(pass_filename, F_OK) != -1) {
        if (remove(pass_filename) != 0) {
            if (verbose) printf("Unable to delete pass file and unregist UID\n");
            return;
        }      
    }
    else {
        if (verbose) printf("inexistent file\n");
        return;
    }
    
    DIR* dir;
    char dirname[13];
    sprintf(dirname, "USERS/%s", u_ist_id);

    dir = opendir(dirname);
    if (dir) {
        closedir(dir);
        rmdir(dirname);
        return;
    }
    else {
        if (verbose) printf("inexistent dir\n");
        return;
    }

}

char* regist_UID(char* message, int i) {  
    int input_index = i;
    char ok[9] = "RRG OK\n\0";
    char nok[9] = "RRG NOK\n\0";
    char* reg_status = (char*) malloc(sizeof(char) * 9);
    strcpy(reg_status, nok);
    
    char* u_ist_id = split_message(message, &input_index, ' ', UID_SIZE + 1);
    if (validate_uid(u_ist_id) != 0) {
        if (verbose) printf("Invalid uid\n");
        free(u_ist_id);
        return reg_status;
    }
    
    char* password = split_message(message, &input_index, ' ', PASSWORD_SIZE + 1);
    if (validate_password(password) != 0) {
        if (verbose) printf("Invalid password\n");
        free(u_ist_id);
        free(password);
        return reg_status;
    }
    
    char* pd_ip = split_message(message, &input_index, ' ', IP_MAX_SIZE + 1);
    if (validate_ip(pd_ip) != 0) {
        if (verbose) printf("Invalid PD IP\n");
        free(u_ist_id);
        free(password);
        free(pd_ip);
        return reg_status;
    }

    char* pd_port = split_message(message, &input_index, '\n', PORT_SIZE + 1);
    if (validate_port(pd_port) != 0) {
        if (verbose) printf("Invalid PD PORT\n");
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
            if (verbose) printf("UID registed successfully\n");
        }
        else {
            if (verbose) printf("Trying to regist with existing UID and different passwords\n");
            strcpy(reg_status, nok);
        }

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
            if (verbose) printf("Unable to create/open file.\n");
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
        if (verbose) printf("UID registed successfully\n");
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

    char* u_ist_id = split_message(message, &input_index, ' ', UID_SIZE + 1);
    if (validate_uid(u_ist_id) != 0) {
        if (verbose) printf("Invalid uid\n");
        free(u_ist_id);
        return log_status;
    }

    char* password = split_message(message, &input_index, '\n', PASSWORD_SIZE + 1);
    if (validate_password(password) != 0) {
        if (verbose) printf("Invalid password\n");
        free(u_ist_id);
        free(password);
        return log_status;
    }

    int v = UID_exists(u_ist_id);
    if (!v){
        if (verbose) printf("UID not registered on server\n");
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
            users_login_info[user_been_treat] = atoi(u_ist_id); // significa que este user efetuou um login com um UID
            if (verbose) printf("User is now logged in with uid: %s\n", u_ist_id);
        }
        else {
            if (verbose) printf("Incorrect password\n");
            strcpy(log_status, nok);        
        }
        free(u_ist_id);
        free(password);
        return log_status;
    }

}

char* request_VC(char* message, int i) {
    int input_index = i;
    char ok[9] = "RRQ OK\n\0"; // deu ok
    char nok[5] = "NOK\n\0";  //deu nok
    char elog[10] = "RRQ ELOG\n\0"; // o user nao efetuou login, nao foi estabelecida uma sessao tcp
    char epd[9] = "RRQ EPD\n\0";  //message not be sent by as to the pd
    char euser[11] = "RRQ EUSER\n\0"; // uid is incorrect
    char efop[10] = "RRQ EFOP\n\0"; //invalid Fop
    char err[9] = "RRQ ERR\n\0";    //REQ message incorrectly formatted
    char* rrq_status = (char*) malloc(sizeof(char) * 11);
    
    char* u_ist_id = split_message(message, &input_index, ' ', UID_SIZE + 1); 
    if (validate_uid(u_ist_id) != 0) {
        if (verbose) printf("Invalid UID\n");
        free(u_ist_id);
        strcpy(rrq_status, euser);
        return rrq_status;
    }
    //verifica se o user efetuou login com algum UID
    if (users_login_info[user_been_treat] == -1) {
        if (verbose) printf("User is not logged in\n");
        free(u_ist_id);
        strcpy(rrq_status, elog);
        return rrq_status;
    }

    //verifica se o user efetuou REQ com um UID existente
    int v = UID_exists(u_ist_id);

    if(!v) {
        if (verbose) printf("UID not registered on server\n");
        strcpy(rrq_status, euser);
        free(u_ist_id);
        return rrq_status;
    }

    //verifica se o user efetuou Req com o uid que efetuou login
    v = user_logged_with_uid(u_ist_id);
    //user nao efetuou REQ para o seu UID com que efetuou login
    if (v != user_been_treat) {
        if (verbose && v != -1) printf("User is not logged in with this UID\n");
        else if (verbose && v == -1) printf("ERROR openning uid login file");
        free(u_ist_id);
        strcpy(rrq_status, euser);
        return rrq_status;
    }

    //leitura e verificacao do RID
    char* rid = split_message(message, &input_index, ' ', RID_SIZE + 1);
    if (validate_rid(rid) != 0) {
        if (verbose) printf("Invalid RID\n");
        strcpy(rrq_status, err);
        free(u_ist_id);
        free(rid);
        return rrq_status;
    }

    //leitura e verificacao de FOP
    char* fop = split_message(message, &input_index, ' ', 2);
    int f = validate_fop(fop);
    if (f == -1) {
        if (verbose) printf("Invalid FOP\n");
        strcpy(rrq_status, efop);
        free(u_ist_id);
        free(rid);
        free(fop);
        return rrq_status;
    }

    //leitura de Fname
    char* fname = split_message(message, &input_index, '\n', FILE_NAME_SIZE + 1);
    if (f == 2) {
        if (fname == NULL) {
            if (verbose) printf("This operation needs a file name\n");
            free(u_ist_id);
            free(rid);
            free(fop);
            free(fname);
            strcpy(rrq_status, err);
            return rrq_status;    
        }
        if (validate_filename(fname) == -1) {
            if (verbose) printf("Invalid filename\n");
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
            if (verbose) printf("This operation doesn't need a file name\n");
            free(u_ist_id);
            free(rid);
            free(fop);
            free(fname);
            strcpy(rrq_status, err);
            return rrq_status;
        }    
    }

    //criacao da mensagem VLC do as para o pd
    char* vlc_message_to_pd = (char*) malloc(sizeof(char) * 45);
    int vc = four_digit_number_generator();
    if (f == 2)
        sprintf(vlc_message_to_pd, "VLC %s %d %s %s\n", u_ist_id, vc, fop, fname);    
    else
        sprintf(vlc_message_to_pd, "VLC %s %d %s\n", u_ist_id, vc, fop);
    
    char* vc_str = (char*) malloc(sizeof(char) * 5);
    sprintf(vc_str, "%d", vc);

    v = get_request_index(NULL, u_ist_id, 2);
    //uid ainda nao tem nenhum request
    if (v == -1) {
        if (verbose) printf("Created a new request for UID: %s\n", u_ist_id);
        Request* request = new_request(u_ist_id, rid, vc_str, fop);
        if (f == 2) {
            request->fname = (char*) malloc(sizeof(char) * (strlen(fname) + 1));
            strcpy(request->fname, fname);
        }
        users_requests[no_requests++] = request; 
    }
    //uid ja tem um request
    else {
        if (verbose) printf("This UID has already a request, it will be overwritten by this new request\n");
        if (f == 2) {
            update_request(users_requests[v], rid, vc_str, fop, fname);
        }
        else {
            update_request(users_requests[v], rid, vc_str, fop, NULL);
        }
    }

    free(vc_str);
    free(rid);
    free(fop);
    free(fname);

    //leitura do pd ip e pd port do ficheiro de registo txt
    FILE* uid_reg_file;

    char reg_filename[28];
    sprintf(reg_filename, "USERS/%s/%s_reg.txt", u_ist_id, u_ist_id);
    uid_reg_file = fopen(reg_filename, "r");
    char pd_ip[16];
    char pd_port[6];
    fscanf(uid_reg_file, "%s %s", pd_ip, pd_port);
    fclose(uid_reg_file);

    char* rvc_status = send_udp(vlc_message_to_pd, pd_ip, pd_port);
    free(vlc_message_to_pd);
    //verificacao do rvc status
    int index = 0;
    char* rvc = split_message(rvc_status, &index, ' ', 4);
    char* uid = split_message(rvc_status, &index, ' ', UID_SIZE + 1);
    char* status = split_message(rvc_status, &index, ' ', 4);
    char r[4] = "RVC\0";

    free(rvc_status);
    
    if (rvc == NULL || uid == NULL || status == NULL) {
        if (verbose) printf("Unexpected RVC message from PD\n");
        strcpy(rrq_status, epd);
        free(u_ist_id);
        free(rvc);
        free(uid);
        free(status);
        return rrq_status;  
    }
    //verifica se o rvc status é do tipo "RVC UID"
    if (strcmp(rvc, r) != 0 || strcmp(uid, u_ist_id) != 0){
        if (verbose) printf("Unexpected RVC message from PD\n");
        strcpy(rrq_status, epd);
        free(u_ist_id);
        free(rvc);
        free(uid);
        free(status);
        return rrq_status;
    }
    if (strcmp(status, nok) == 0) {
        if (verbose) printf("Unexpected RVC message from PD\n");
        strcpy(rrq_status, err);
    }
    else
        strcpy(rrq_status, ok);

    free(u_ist_id);
    free(rvc);
    free(uid);
    free(status);
    if (verbose) printf("Requested sucessfully\n");
    return rrq_status;
}

char* check_VC(char* message, int i) {
    int input_index = i;
    char failed[7] = "RAU 0\n\0";
    char* rau_status = (char*) malloc(sizeof(char)*10);
    strcpy(rau_status, failed);

    char* u_ist_id = split_message(message, &input_index, ' ', UID_SIZE + 1); 
    if (validate_uid(u_ist_id) != 0) {
        if (verbose) printf("Invalid UID\n");
        free(u_ist_id);
        return rau_status;
    }

    //verifica se o user efetuou login com algum UID
    if (users_login_info[user_been_treat] == -1) {
        if (verbose) printf("User is not logged in\n");
        free(u_ist_id);
        return rau_status;
    }

    //verifica se o user efetuou AUT com um UID existente
    int v = UID_exists(u_ist_id);

    if(!v) {
        if (verbose) printf("UID not registered on server\n");
        free(u_ist_id);
        return rau_status;
    }

    //verifica se o user efetuou AUT com o uid que efetuou login
    int u = user_logged_with_uid(u_ist_id);
    //user nao efetuou AUT para o seu UID com que efetuou login
    if (u != user_been_treat) {
        if (verbose && v != -1) printf("User is not logged in with this UID\n");
        else if (verbose && v == -1) printf("ERROR openning uid login file");
        free(u_ist_id);
        return rau_status;
    }

    //leitura e verificacao do RID
    char* rid = split_message(message, &input_index, ' ', RID_SIZE + 1);
    if (validate_rid(rid) != 0) {
        if (verbose) printf("Invalid RID\n");
        free(u_ist_id);
        free(rid);
        return rau_status;
    }
    //verifica se o RID existe para o UID e se nao exitir RID entao devolve RAU 0, como em todos os outros casos de erro nesta funcao
    if (!check_rid_exists(rid, u_ist_id)) {
        if (verbose) printf("RID %s do not exists for UID %s\n", rid, u_ist_id);
        free(u_ist_id);
        free(rid);
        return rau_status;    
    }

    char* vc = split_message(message, &input_index, '\n', VC_SIZE + 1);
    if(validate_vc(vc) != 0) {
        if (verbose) printf("Invalid VC\n");
        free(u_ist_id);
        free(rid);
        free(vc);
        return rau_status;
    }
    int request_index = get_request_index(rid, u_ist_id, 0);
    if (strcmp(users_requests[request_index]->vc, vc) == 0) {
        //verifica se o tid ja foi criado
        if (users_requests[request_index]->tid == NULL) {
            char* tid = (char*) malloc(sizeof(char) * (TID_SIZE + 1));
            sprintf(tid, "%d", four_digit_number_generator());
            //se existir um tid repetido neste u_ist_id gera outro tid
            while(tid_exists_for_uid(u_ist_id, tid) != -1)
                sprintf(tid, "%d", four_digit_number_generator()); 
            sprintf(rau_status, "RAU %s\n", tid);
            users_requests[request_index]->tid = (char*) malloc(sizeof(char) * (TID_SIZE + 1));
            strcpy(users_requests[request_index]->tid, tid);
            free(tid);
        }
        //caso ja tenha um tid mantem se o mesmo nao se altera
        else {
            sprintf(rau_status, "RAU %s\n", users_requests[request_index]->tid);   
        }
        
    }
    if (verbose && strcmp(rau_status, failed) == 0) printf("Incorrect validation code\n");
    if (verbose && strcmp(rau_status, failed) != 0) printf("Tid generated successfully\n");
    free(u_ist_id);
    free(rid);
    free(vc);
    return rau_status;
}

char* vld_operation(char* message, int i) {
    int input_index = i;
    char err[5] = "ERR\n\0";
    char* cnf_answer = (char*) malloc(sizeof(char) * (17 + FILE_NAME_SIZE + 2));
    
    char* u_ist_id = split_message(message, &input_index, ' ', UID_SIZE + 1); 
    if (validate_uid(u_ist_id) != 0) {
        if (verbose) printf("Invalid UID\n");
        free(u_ist_id);
        strcpy(cnf_answer, err);
        return cnf_answer;
    }
    //verifica se o uid existe
    int v = UID_exists(u_ist_id);

    if(!v) {
        if (verbose) printf("UID not registered on server\n");
        strcpy(cnf_answer, err);
        free(u_ist_id);
        return cnf_answer;
    }

    //leitura do tid e validacao
    char* tid = split_message(message, &input_index, '\n', TID_SIZE + 1);
    if (validate_tid(tid) != 0) {
        if (verbose) printf("Invalid TID\n");
        strcpy(cnf_answer, err);
        free(u_ist_id);
        free(tid);
        return cnf_answer;
    }
    //verifica se o tid é igual para algum request deste u_ist_id
    v = tid_exists_for_uid(u_ist_id, tid);
    if (v == -1) {
        if (verbose) printf("Incorrect TID\n");
        sprintf(cnf_answer, "CNF %s %s E\n", u_ist_id, tid);
    }
    else {
        if (verbose) printf("Correct TID, successful validation\n");
        if (strcmp(users_requests[v]->fop, "X") == 0)
            logout_user(u_ist_id);
        int f = validate_fop(users_requests[v]->fop);
        if (f == 2)
            sprintf(cnf_answer, "CNF %s %s %s %s\n", u_ist_id, tid, users_requests[v]->fop, users_requests[v]->fname);
        else if (f == 1)
            sprintf(cnf_answer, "CNF %s %s %s\n", u_ist_id, tid, users_requests[v]->fop);
    }
   
    free(u_ist_id);
    free(tid);
    return cnf_answer;
}

char* unregist_UID(char* message, int i) {
    int input_index = i;
    char ok[8] = "RUN OK\n\0"; // deu ok
    char nok[9] = "RUN NOK\n\0";  //deu nok
    char* run_status = (char*) malloc(sizeof(char) * 9);
    strcpy(run_status, nok);

    char* u_ist_id = split_message(message, &input_index, ' ', UID_SIZE + 1);
    if (validate_uid(u_ist_id) != 0) {
        if (verbose) printf("Invalid uid\n");
        free(u_ist_id);
        return run_status;
    }

    char* password = split_message(message, &input_index, ' ', PASSWORD_SIZE + 1);
    if (validate_password(password) != 0) {
        if (verbose) printf("Invalid password\n");
        free(u_ist_id);
        free(password);
        return run_status;
    }

    int v = UID_exists(u_ist_id);
    if (!v){
        if (verbose) printf("UID not registered on server\n");
        free(u_ist_id);
        free(password);
        return run_status;
    }
    else {
        if (equal_passwords(u_ist_id, password)) {
            strcpy(run_status, ok);
            logout_user(u_ist_id);
            delete_uid_files(u_ist_id);
            if (verbose) printf("UID deleted from AS server successfuly\n");
        }
        else 
            if (verbose) printf("Incorrect password\n");
    }

    free(u_ist_id);
    free(password);
    return run_status;

}

char* treat_udp_message(char* message) {
    int input_index = 0;
    char err[5] = "ERR\n\0";

    if (strcmp(message, "") == 0) return NULL;

    char* action = split_message(message, &input_index, ' ', 4);
    if (action == NULL) {
        printf("action: %s\n", action);
        if (verbose) printf("Invalid action\n");
        free(action);
        char* answer = (char*) malloc(sizeof(char) * 5);
        strcpy(answer, err);
        return answer;
    }

    char reg[4] = "REG\0";
    if (strcmp(action, reg) == 0) {
        char* answer = regist_UID(message, input_index);
        free(action);
        return answer;
        //trata de verificar o REG
    }

    char unr[4] = "UNR\0";
    if (strcmp(action, unr) == 0) {
        char* answer = unregist_UID(message, input_index);
        free(action);
        return answer;
        //trata a operacao unr
    }

    char vld[4] = "VLD\0";
    if (strcmp(action, vld) == 0) {
        char* answer = vld_operation(message, input_index);
        free(action);
        return answer;
        //trata a operacao vld
    }

    //nenhuma operacao valida
    if (verbose) printf("Invalid action\n");
    char* answer = (char*) malloc(sizeof(char) * 5);
    strcpy(answer, err);
    return answer;
}

char* treat_tcp_message(char* message) {
    int input_index = 0;
    char err[5] = "ERR\n\0";

    if (strcmp(message, "") == 0) return NULL;

    char* action = split_message(message, &input_index, ' ', 4);
    if (action == NULL) {
        if (verbose) printf("Invalid action\n");
        free(action);
        char* answer = (char*) malloc(sizeof(char) * 5);
        strcpy(answer, err);
        return answer;
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

     //nenhuma operacao valida
    if (verbose) printf("Invalid action\n");
    char* answer = (char*) malloc(sizeof(char) * 5);
    strcpy(answer, err);
    return answer;
}

void handle_sock_closed(int sig) { 
    if (sig == 13) socket_closed = TRUE;
} 

void close_server(int sig) {
    if (sig == 2) running = FALSE;
}

int main(int argc, char **argv) {

    if (argc < 1 || argc > 4) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    signal(SIGPIPE, handle_sock_closed);
    signal(SIGINT, close_server);

    users_requests = (Request**) malloc(sizeof(Request*) * MAX_REQUESTS);

    for (int i = 0; i < MAX_USERS; i++)
        users_login_info[i] = -1; //coloca todas as posicoes a -1 para informar que os users que se podem ligar ao as nao efetuaram login, se efetuarem um login bem sucedido entao é colocado a 1 na sua posicao
        
    char* as_port = (char*) malloc(sizeof(char) * (PORT_SIZE + 1));

    int flagPort = FALSE;

    char c;
    while ((c = getopt (argc, argv, "p:v")) != -1) {
        switch (c) {
        case 'p':
            strcpy(as_port, optarg);
            flagPort = TRUE;
            break;
        case 'v':
            verbose = TRUE;
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
        if (verbose) printf("invalid as_port\n");
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

    int fd_udp = open_udp(as_port);
    if (fd_udp == -1) {
        printf("can't create socket\n");
        free(as_port);
        close(fd_udp);
        exit(EXIT_FAILURE);
    }

    int fd_user = open_tcp(as_port);
    if (fd_user == -1) {
        printf("can't create socket\n");
        free(as_port);
        close(fd_user);
        exit(EXIT_FAILURE);
    }
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    char* in_str = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    FD_ZERO(&inputs); 
    FD_SET(fd_udp, &inputs);
    FD_SET(fd_user, &inputs);
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
                if (FD_ISSET(fd_udp, &testfds)) {
                    if (verbose) printf("read udp\n");
                    struct sockaddr_in addr;
                    socklen_t addrlen = sizeof(addr);
                    ssize_t n;
                    n = recvfrom (fd_udp, in_str, BUFFER_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
                    if (n == -1) {
                        if (verbose)
                            printf("cant send message to PD\n");
                        break;
                    }
                    in_str[n] = 0;
                    char* answer = treat_udp_message(in_str);
                    if (answer != NULL) {
                        n = sendto (fd_udp, answer, strlen(answer), 0, (struct sockaddr*)&addr, addrlen);
                        if (n == -1) {
                            if (verbose) 
                                printf("cant send message to PD\n");
                            break;
                        }
                        
                    }
                    free(answer);
                }
                if (FD_ISSET(fd_user, &testfds)) {
                    if (verbose) printf("read tcp\n");
                    int newfd;
                    struct sockaddr_in addr;
                    socklen_t addrlen;
                    addrlen = sizeof(addr);
                    if ((newfd = accept(fd_user, (struct sockaddr*)&addr, &addrlen)) == -1 ) /*error*/ exit(1);
                    for (int i = 0; i < MAX_USERS; i++) {
                        if (users[i] == -1) {
                            if (verbose) printf("added user\n");
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
                        if(socket_closed || n <= 0) {
                            if (verbose) printf("user disconnected\n");
                            FD_CLR(users[i], &inputs);
                            close(users[i]);
                            disconnect_user();
                            users[i] = -1;
                            socket_closed = FALSE;
                            break;
                        } 
                        char* answer = treat_tcp_message(in_str);
                        if (answer != NULL) n = write (users[i], answer, strlen(answer));
                        if (socket_closed || n <= 0) {
                            if (verbose) printf("user disconnected\n");
                            FD_CLR(users[i], &inputs);
                            close(users[i]);
                            disconnect_user();
                            users[i] = -1;
                            socket_closed = FALSE;
                        } 
                        free(answer);
                    }
                }
                break;
        }
    }

    for (int i = 0; i < no_requests; i++) {
        free(users_requests[i]->uid);
        free(users_requests[i]->rid);
        free(users_requests[i]->vc);
        free(users_requests[i]->fop);
        if (users_requests[i]->tid != NULL) free(users_requests[i]->tid);
        if (users_requests[i]->fname != NULL) free(users_requests[i]->fname);
        free(users_requests[i]);
    }
    free(users_requests);

    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i] != -1)
            close(users[i]);
    }
    free(as_port);
    free(in_str);
    free(users);
    close(fd_udp);
    close(fd_user);

    return 0;
}