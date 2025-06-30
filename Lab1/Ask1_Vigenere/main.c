#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define N 50

char* Vigenere_cipher(char *plain_txt, char *key);
char* Vigenere_decipher(char *cipher_txt, char *key);
char* Vigenere_SpecialCharRemove(char *text);

int main() {

    char *plain = "ATTACKATDAWN";
    char *key = "LEMON";

    char *cipher_txt = Vigenere_cipher(plain, key);
    char *decipher_txt = Vigenere_decipher(cipher_txt, key);

    printf("Plain: %s <> len = %lu\n", plain, strlen(plain));
    printf("cipher: %s <> len = %lu\n", cipher_txt, strlen(cipher_txt));
    printf("decipher: %s <> len = %lu\n", decipher_txt, strlen(decipher_txt));

    return 0;
}


char* Vigenere_cipher(char *plain_txt, char *key) {
    char *plain = Vigenere_SpecialCharRemove(plain_txt);

    int plain_length = strlen(plain);
    int key_length = strlen(key);
    char *cipher_txt = malloc( (plain_length+1)*sizeof(char));

    int plain_offset, key_offset;
    int ASCII_offset = 65;
    for(int i=0; i<plain_length; i++){
        plain_offset = plain[i];
        key_offset = key[i % key_length];
        cipher_txt[i] = ASCII_offset + ((plain_offset + key_offset) % 26);
    }
    cipher_txt[plain_length] = '\0';
    return cipher_txt;
}

char* Vigenere_decipher(char *cipher_txt, char *key) {
    int length = strlen(cipher_txt);
    int key_length = strlen(key);
    char *plain_txt = malloc( (length+1)*sizeof(char));

    int cipher_offset, key_offset;
    int ASCII_offset = 65;
    for(int i=0; i<length; i++){
        cipher_offset = cipher_txt[i];
        key_offset = key[i % key_length];
        plain_txt[i] = (( cipher_offset - key_offset + 26) % 26) + ASCII_offset;
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

