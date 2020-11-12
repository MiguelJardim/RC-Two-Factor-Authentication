#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aux/validation.h"
#include "../aux/conection.h"
#include "../aux/constants.h"

typedef struct credentials {
    char* id;
    char* password;
} *credentials;

credentials user;

char* command_to_string(char command) {
    if (command == 'L') return "list\0";
    else if (command == 'R') return "retrieve\0";
    else if (command == 'U') return "upload\0";
    else if (command == 'D') return "delete\0";
    else if (command == 'X') return "remove\0";
    else return NULL;
}

char* unregister(char* as_ip, char* as_port) {
    char* message = (char*) malloc(sizeof(char) * 20);

    if (sprintf(message, "UNR %s %s\n", user->id, user->password) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }

    char* answer = send_udp(message, as_ip, as_port);
    free(message);

    return answer;

}

/** returns -2 in case of invalid as response
 *  returns 1 in case of an operation that requires a filename
 *  returns 0 in case of an operation that does not require a filename
 *  returns -1 in case of an unexpected answer
 * 
 *  instruction will store the operation identifier
*/
int read_vlc(char* input, char* vlc_out, int* instruction, char* file_name) {

    int index = 0;

    // read VLC
    char vlc_str[4] = "VLC\0";

    char* aux = split(input, &index, ' ', 4);
    if (aux == NULL) {
        free(aux);
        return -1;
    }

    if (strcmp(aux, vlc_str) != 0) {
        free(aux);
        return -1;
    }
    free(aux);

    // read user id
    char* uid = split(input, &index, ' ', (UID_SIZE + 1));

    if (uid == NULL) {
        return -2;
    }

    if (strcmp(uid, user->id) != 0) {
        free(uid);
        return -2;
    }
    free(uid);

    // read vlc
    char* vlc = split(input, &index, ' ', VLC_SIZE + 1);

    if (vlc == NULL) {
        free(vlc);
        return -2;   
    }

    int out = 0;
    // read operation
    int saved_index = index;
    
    char* instruction_read = NULL;
    char* file_name_read = NULL;

    instruction_read = split(input, &index, ' ', 2);

    // commands R, U and D need extra argument
    if (instruction_read != NULL && (instruction_read[0] == 'R' || instruction_read[0] == 'U' || instruction_read[0] == 'D')) {
        
        file_name_read = split(input, &index, '\n', FILE_NAME_SIZE + 1);
        if (file_name_read == NULL) {
            free(vlc);
            free(instruction_read);
            free(file_name_read);
            return -2;
        }

        strcpy(file_name, file_name_read);
        free(file_name_read);
        *instruction = instruction_read[0];
        // instruction with file name
        out = 1;
        
    }
    else if (instruction_read == NULL) {
        instruction_read = split(input, &saved_index, '\n', 2);
        if (instruction_read == NULL) {
            free(vlc);
            free(instruction_read);
            return -2;
        }
        
        if ((instruction_read[0] == 'X' || instruction_read[0] == 'L')) {
            *instruction = instruction_read[0];
        } 
    }
    else {
        free(instruction_read);
        return -2;
    }

    strcpy(vlc_out, vlc);

    free(instruction_read);
    free(vlc);

    return out;
}

char* read_reg_command(char* input, char* pd_ip, char* pd_port) {

    int input_index = 0;

    // read reg
    char reg[4] = "reg\0";

    char* aux = split(input, &input_index, ' ', 4);
    if (aux == NULL) {
        printf("invalid command\n");
        free(aux);
        return NULL;
    }
    
    if (strcmp(aux, reg) != 0) {
        printf("reg command expected\n");
        free(aux);
        return NULL;
    }

    // read ist id

    char* uid = split(input, &input_index, ' ', UID_SIZE + 1);

    if (uid == NULL) {
        printf("invalid uid\n");
        free(aux);
        free(uid);
        return NULL;
    }

    if (validate_uid(uid) == -1) {
        printf("invalid uid: %s\n", uid);
        free(aux);
        free(uid);
        return NULL;
    }

    // read password
    char* password = split(input, &input_index, '\n', PASSWORD_SIZE + 1);

    if (password == NULL) {
        printf("invalid password\n");
        free(aux);
        free(uid);
        free(password);
        return NULL;
    }

    if (validate_password(password) == -1) {
        printf("invalid password: %s\n", password);
        free(aux);
        free(uid);
        free(password);
        return NULL;
    }

    // REG UID pass PDIP PDport
    char* message = (char*) malloc(sizeof(char) * 45);

    if (sprintf(message, "REG %s %s %s %s\n", uid, password, pd_ip, pd_port) < 0) {
        fprintf(stderr, "sprintf error\n");
        exit(EXIT_FAILURE);
    }

    free(aux);
    strcpy(user->id, uid);
    strcpy(user->password, password);
    free(uid);
    free(password);

    return message;
}

int main(int argc, char **argv) {

    if (argc < 2 || argc > 8) {
        fprintf(stderr, "usage: %s file", argv[0]);
        exit(EXIT_FAILURE);
    }

    int as_ip_flag = FALSE, pd_port_flag = FALSE, as_port_flag = FALSE;

    char* pd_ip = (char*) malloc(sizeof(char) * IP_MAX_SIZE + 1);
    strcpy(pd_ip, argv[1]);

    char* pd_port = (char*) malloc(sizeof(char) * PORT_SIZE + 1);

    char* as_ip = (char*) malloc(sizeof(char) * IP_MAX_SIZE + 1);
    char* as_port = (char*) malloc(sizeof(char) * PORT_SIZE + 1);

    char c;
    while ((c = getopt (argc, argv, "d:n:p:")) != -1) {
        switch (c) {
        case 'd':
            strcpy(pd_port, optarg);
            pd_port_flag = TRUE;
            break;
        case 'n':
            strcpy(as_ip, optarg);
            as_ip_flag = TRUE;
            break;
        case 'p':
            strcpy(as_port, optarg);
            as_port_flag = TRUE;
            break;
        default:
            abort();
        }
    }
    
    if (!as_ip_flag) strcpy(as_ip, pd_ip);
    if (!pd_port_flag) {
        strcpy(pd_port, PD_PORT);
    }
    if (!as_port_flag) {
        strcpy(as_port, AS_PORT);
    }

    int error = FALSE;
    if (validate_ip(pd_ip) == -1) {
        printf("invalid pd_ip: %s\n", pd_ip);
        error = TRUE;
    }
    if (as_ip_flag && validate_ip(as_ip) == -1) {
        printf("invalid as_ip: %s\n", as_ip);
        error = TRUE;
    }
    if (pd_port_flag && validate_port(pd_port) == -1) {
        printf("invalid pd_port: %s\n", pd_port);
        error = TRUE;
    }
    if (as_port_flag && validate_port(as_port) == -1) {
        printf("invalid as_port: %s\n", as_port);
        error = TRUE;
    }

    if (error) {
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }

    int fd_as = open_udp(pd_port);
    if (fd_as == -1) {
        printf("Connection error.\n");
        free(pd_ip);
        free(pd_port);
        free(as_ip);
        free(as_port);
        exit(EXIT_FAILURE);
    }

    user = (credentials) malloc(sizeof(struct credentials));
    user->id = (char*) malloc(sizeof(char) * UID_SIZE + 1);
    user->password = (char*) malloc(sizeof(char) * PASSWORD_SIZE + 1);

    char* in_str = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    fd_set inputs, testfds;
    struct timeval timeout;
    int out_fds,n;
    FD_ZERO(&inputs); 
    FD_SET(0,&inputs);
    FD_SET(fd_as, &inputs);
    int running = TRUE;
    while(running) {
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
                if(FD_ISSET(0,&testfds)) {
                    if((n=read(0,in_str,BUFFER_SIZE))!=0) {
                        if(n==-1) exit(1);
                        in_str[n]=0;

                        // check if user input is "exit"
                        char exit_txt[6] = "exit\n\0";
                        if (strcmp(in_str, exit_txt) == 0) {
                            running = FALSE;
                            char expected_message[8] = "RUN OK\n\0";
                            char* answer = unregister(as_ip, as_port);
                            if (strcmp(expected_message, answer) == 0) {
                                printf("unregistration successfull\n");
                            }
                            else {
                                printf("unregistration failed\n");
                            }
                            free(answer);
                            break;
                        }
                        
                        char* message = read_reg_command(in_str, pd_ip, pd_port);
                        if (message == NULL) break;

                        char* answer = send_udp(message, as_ip, as_port);
                        if (answer == NULL) {
                            free(message);
                            free(answer);
                            running = FALSE;
                            break;
                        }
                        char expected_message[8] = "RRG OK\n\0";

                        if (strcmp(expected_message, answer) == 0) {
                            printf("Registration successfull\n");
                        }
                        else {
                            printf("%s", answer);
                        }

                        free(message);
                        free(answer);

                    }
                }
                if (FD_ISSET(fd_as, &testfds)) {
                    struct sockaddr_in addr;
                    socklen_t addrlen=sizeof(addr);
                    n= recvfrom (fd_as,in_str,BUFFER_SIZE,0, (struct sockaddr*)&addr,&addrlen);
                    if(n==-1) /*error*/ break;     
                    
                    int instruction = 0; 
                    char* file_name = (char*) malloc(sizeof(char) * (FILE_NAME_SIZE + 1));
                    char* vlc = (char*) malloc(sizeof(char) * VLC_SIZE + 1);
                    int out = read_vlc(in_str, vlc, &instruction, file_name);
                    if (out == 0 && instruction != 0) {
                        printf("VC=%s, %s\n", vlc, command_to_string(instruction));
                        free(vlc);
                        free(file_name);
                    }
                    else if (out == 1 && instruction != 0) {
                        printf("VC=%s, %s: %s\n", vlc, command_to_string(instruction), file_name);
                        free(vlc);
                        free(file_name);
                    }

                    if (out == 0 || out == 1) {
                        char* message = (char*) malloc(sizeof(char) * (UID_SIZE + 9));
                        if (sprintf(message, "RVC %s OK\n", user->id) < 0) {
                            free(message);
                            fprintf(stderr, "sprintf error\n");
                            exit(EXIT_FAILURE);
                        }
                        
                        sendto(fd_as, message, UID_SIZE + 9, 0, (struct sockaddr*)&addr, addrlen);
                        free(message);
                    }
                    else if (out == -2) {
                        char* message = (char*) malloc(sizeof(char) * (UID_SIZE + 9));
                        if (sprintf(message, "RVC %s NOK\n", user->id) < 0) {
                            free(message);
                            fprintf(stderr, "sprintf error\n");
                            exit(EXIT_FAILURE);
                        }
                        sendto(fd_as, message, UID_SIZE + 9, 0, (struct sockaddr*)&addr, addrlen);
                        free(message);
                    }
                } 
                break;
        }
    }

    free(pd_ip);
    free(pd_port);
    free(as_ip);
    free(as_port);
    free(in_str);

    close(fd_as);

    free(user->id);
    free(user->password);
    free(user);

    return 0;
}