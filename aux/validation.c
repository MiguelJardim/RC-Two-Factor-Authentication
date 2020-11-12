#include "validation.h"
#include "constants.h"

char* split(char* input, int* index, char separator, int size) {
    char* output = (char*) malloc(sizeof(char) * size);
    int output_index = 0;

    char c = input[(*index)++];
    if (c == separator) {
        free(output);
        return NULL;
    }

    while (c != separator && c != '\0' && c != EOF) {
        if (output_index == size - 1) {
            free(output);
            return NULL;
        }
        output[output_index++] = c;
        c = input[(*index)++];
    }

    output[output_index] = '\0';

    return output;
}

int validate_uid(char* uid) {
    if (uid == NULL) return -1;

    if (strlen(uid) != UID_SIZE) return -1;
    if (uid[0] == '0') return -1;

    for (int i = 1; i < UID_SIZE; i++) {
        if (uid[i] < '0' || uid[i] > '9') return -1;
    }

    return 0;
}

int validate_tid(char* tid) {
    if (tid == NULL) return -1;

    if (strlen(tid) != TID_SIZE) return -1;

    for (int i = 0; i < TID_SIZE; i++) {
        if (tid[i] < '0' || tid[i] > '9') return -1;
    }

    return 0;
}

int validate_rid(char* rid) {
    return validate_tid(rid);
}

int validate_password(char* password) {
    if (password == NULL) return -1;

    if (strlen(password) != PASSWORD_SIZE) return -1;
    
    for (int i = 0; i < PASSWORD_SIZE; i++) {
        if (!((password[i] >= '0' && password[i] <= '9') || (password[i] >= 'a' && password[i] <= 'z') || (password[i] >= 'A' && password[i] <= 'Z'))) return -1;
    }

    return 0;
}

int validate_ip(char* ip) {
    if (ip == NULL) return -1;

    if (strlen(ip) < 7 || strlen(ip) > IP_MAX_SIZE) return -1;

    char* validated_ip = (char*) malloc(sizeof(char) * (IP_MAX_SIZE + 1));
    int index = 0;
    int validated_index = 0;
    char c = ip[index++];
    int digits = 0;
    int dots = 0;
    
    while (c != '\0') {

        digits = 0;

        if (c < '0' || c > '9') {
            free(validated_ip);
            return -1;
        }

        if (c != '0') {
            validated_ip[validated_index++] = c;
            digits++;  
        }

        c = ip[index++];
        while (c != '.' && c != '\0' && digits < 3) {
            
            if (c < '0' || c > '9') {
                free(validated_ip);
                return -1;
            }

            validated_ip[validated_index++] = c;
            digits++;

            c = ip[index++];
        }

        if (digits == 0) {
            free(validated_ip);
            return -1;
        }
        else if (c == '.' && dots < 3) {
            validated_ip[validated_index++] = c;
            dots++;
        }
        else if (c == '\0' && dots == 3) {
            validated_ip[validated_index++] = c;
        }
        else {
            free(validated_ip);
            return -1;
        }

        if (index <= (int) strlen(ip)) c = ip[index++];

    }

    strcpy(ip, validated_ip);
    free(validated_ip);

    return 0;
}

int validate_port(char* port) {
    if (port == NULL) return -1;

    if (strlen(port) != PORT_SIZE) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
}

int validate_vc(char* vc) {
    if (vc == NULL) return -1;
    if (strlen(vc) != VC_SIZE) return -1;
    if (vc[0] == '0') return -1;

    for (int i = 1; i < 4; i++) {
        if (vc[i] < '0' || vc[i] > '9') return -1;
    }

    return 0;
}

int validate_fop(char* fop) {
    if (fop == NULL) return -1;
    int i = -1;
    if (strlen(fop) != 1) return -1;

    if (strcmp(fop, "L") == 0 || strcmp(fop, "X") == 0)
        i = 1;
    if (strcmp(fop, "R") == 0 || strcmp(fop, "U") == 0 || strcmp(fop, "D") == 0)
        i = 2;
    
    return i;
}

int validate_filename(char* fname) {
    if (!fname) return -1;
    if (strlen(fname) > FILE_NAME_SIZE) return -1;

    int i = 0;
    char c = fname[i++];
    while (i < (int) strlen(fname) && c != '\0') {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '.')) return -1;
        c = fname[i++];
    }

    c = fname[i];
    if (c != '\0') return -1;

    return 0;
}

int is_number(char* number) {
    if (number == NULL) return FALSE;

    for (int i = 0; i < (int) strlen(number); i++) {
        if (number[i] < '0' || number[i] > '9') return FALSE;
    }
    return TRUE;
}