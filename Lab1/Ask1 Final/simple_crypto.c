#include "simple_crypto.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


static char Acceptable_Chars[62]  = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                                     'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                                     'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

char *SpecialCharRemove(char *text) {
    int initial_size = strlen(text);
    int final_size = 0;
    char *temp = malloc( (initial_size+1)*sizeof(char));

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
    return temp;
}


char* OTP_cipher(char *plain_txt, char *key) {
    char* plain = SpecialCharRemove(plain_txt);
    int length = strlen(plain);
    char *cipher_txt = malloc( (length+1)*sizeof(char));

    for(int i=0; i<length; i++){
        cipher_txt[i] = plain[i] ^ key[i % KEY_SIZE];
    }

    cipher_txt[length] = '\0';

    return cipher_txt;
}

char* OTP_decipher(char *cipher_txt, char *key) {
    int length = strlen(cipher_txt);
    char *plain_txt = malloc( (length+1)*sizeof(char));

    for(int i=0; i<length; i++){
        plain_txt[i] = cipher_txt[i] ^ key[i % KEY_SIZE];
    }
    plain_txt[length] = '\0';

    return plain_txt;
}

char* Caesar_cipher(char* plain_txt, int key) {
    char* plain = SpecialCharRemove(plain_txt);
    int length = strlen(plain);
    char *cipher_txt = malloc( (length+1)*sizeof(char));

    for(int i=0; i<length; i++){
        for(int j=0; j<62; j++){
            if (plain_txt[i] == Acceptable_Chars[j]){
                int shift_ammount = key % 62;
                cipher_txt[i] = Acceptable_Chars[ (j + shift_ammount) % 62];
                break;
            }
        }
    }
    cipher_txt[length] = '\0';
    return cipher_txt;
}

char* Caesar_decipher(char* cipher_txt, int key) {
    int length = strlen(cipher_txt);
    char *plain_txt = malloc( (length+1)*sizeof(char));

    for(int i=0; i<length; i++){
        for(int j=0; j<62; j++){
            if (cipher_txt[i] == Acceptable_Chars[j]){
                int shift_ammount = key % 62;
                if(j - shift_ammount < 0) {
                    plain_txt[i] = Acceptable_Chars[62 + (j - shift_ammount)];
                }
                else{
                    plain_txt[i] = Acceptable_Chars[j - shift_ammount];
                }
                break;
            }
        }
    }

    plain_txt[length] = '\0';
    return plain_txt;
}

char *Vigenere_SpecialCharRemove(char *text) {
    int initial_size = strlen(text);
    char *temp = malloc( (initial_size+1)*sizeof(char));
    int final_size = 0;

    for(int i=0; i<initial_size; i++){
        if((text[i]) >= 65 && (text[i]) <= 90){
            temp[final_size] = text[i];
            final_size++;
        }
    }
    temp[final_size] = '\0';
    return temp;
}


char* Vigenere_cipher(char *plain_txt, char *key) {
    char *plain = Vigenere_SpecialCharRemove(plain_txt);

    int plain_length = strlen(plain);
    int key_length = strlen(key);
    char *cipher_txt = malloc( (plain_length+1)*sizeof(char));

    for(int i=0; i<plain_length; i++){
        cipher_txt[i] = ((plain[i] + key[i % key_length]) % 26);
        cipher_txt[i] += 'A';
    }
    cipher_txt[plain_length] = '\0';
    return cipher_txt;
}

char* Vigenere_decipher(char *cipher_txt, char *key) {
    int length = strlen(cipher_txt);
    int key_length = strlen(key);
    char *plain_txt = malloc( (length+1)*sizeof(char));

    for(int i=0; i<length; i++){
        plain_txt[i] = ( cipher_txt[i] - key[i % key_length] + 26 ) % 26;
        plain_txt[i] += 'A';
    }

    plain_txt[length] = '\0';
    return plain_txt;
}



