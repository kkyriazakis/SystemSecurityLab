#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define N 50

static char Acceptable_Chars[62]  = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                                    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

char* OTP_cipher(char plain_txt[N], char key[N]);
void SpecialCharRemove(char *text);
char* OTP_decipher(char cipher_txt[N], char key[N]);

int main() {

    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0){
        printf("Error Opening /dev/urandom");
        return -1;
    }
    char key[N];
    read(randomData, key, sizeof(key));

    char plain[N] = "THISISATESTOFOTPANDOTHER";
    char *cipher_txt = OTP_cipher(plain, key);
    char *decipher_txt = OTP_decipher(cipher_txt, key);

    printf("Plain: %s == len = %lu\n", plain, strlen(plain));
    printf("key: %s == len = %lu\n", key, strlen(key));
    printf("cipher: %s == len = %lu\n", cipher_txt, strlen(cipher_txt));
    printf("cipher: %s == len = %lu\n", decipher_txt, strlen(decipher_txt));

    return 0;
}


char* OTP_cipher(char plain_txt[N], char key[N]) {
    char *cipher_txt = malloc(N);
    SpecialCharRemove(plain_txt);

    int length = strlen(plain_txt);

    for(int i=0; i<length; i++){
        cipher_txt[i] = plain_txt[i] ^ key[i];
    }

    cipher_txt[length] = '\0';

    return cipher_txt;
}

char* OTP_decipher(char cipher_txt[N], char key[N]) {
    char *plain_txt = malloc(N);
    int length = strlen(cipher_txt);

    for(int i=0; i<length; i++){
        plain_txt[i] = cipher_txt[i] ^ key[i];
    }

    plain_txt[length] = '\0';

    return plain_txt;
}

void SpecialCharRemove(char *text) {
    char temp[N];
    int initial_size = strlen(text);
    int final_size = 0;

    for(int i=0; i<initial_size; i++){
        for(int j=0; j<62; j++) {
            if(text[i] == Acceptable_Chars[j] ){
                temp[final_size] = text[i];
                final_size++;
                break;
            }
        }
    }
    temp[final_size] = '\0';
    strcpy(text,temp);
}

