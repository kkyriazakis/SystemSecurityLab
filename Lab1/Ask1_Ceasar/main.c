#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define N 50

static char Acceptable_Chars[62]  = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                                     'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                                     'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

char* Caesar_cipher(char* plain_txt, int key);
char* Caesar_decipher(char* cipher_txt, int key);
char* SpecialCharRemove(char *text);

int main() {

    char plain[2048];
    int key;

    printf("[Caesars] input: ");
    fgets(plain,sizeof(plain), stdin);

    //scanf("[Caesars] key: %d", &key);
    //key = 4;
    fgets(key,sizeof(key), stdin);

    char *cipher_txt = Caesar_cipher(plain, key);
    printf("[Caesars] encrypted: %s\n", cipher_txt);

    char *decipher_txt = Caesar_decipher(cipher_txt, key);
    printf("[Caesars] decrypted: %s\n", decipher_txt);

    return 0;
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

