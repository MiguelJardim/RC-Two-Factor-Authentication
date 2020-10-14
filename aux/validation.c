#include "validation.h"

char* split(char* input, int* index, char separator, int size) {
    char* output = (char*) malloc(sizeof(char) * size);
    int output_index = 0;

    char c = input[(*index)++];
    if (c == separator) {
        free(output);
        return NULL;
    }

    while (c != separator && c != EOF) {
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
    if (strlen(port) != 5) return -1;

    for (int i = 0; i < 5; i++) {
        if (port[i] < '0' || port[i] >'9') return -1;
    }
    if (port[0] == '0') return -1;
    return 0;
}