#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "simple_crypto.h"

int main() {
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0){
        printf("Error Opening /dev/urandom");
        return -1;
    }
    char key_OTP[KEY_SIZE];
    read(randomData, key_OTP, sizeof(key_OTP));

    char plain[2048];

    // ============= OTP =============
    printf("[OTP] input: ");
    fgets(plain,sizeof(plain), stdin);

    char *cipher_txt = OTP_cipher(plain, key_OTP);
    printf("[OTP] encrypted: %s\n", cipher_txt);

    char *decipher_txt = OTP_decipher(cipher_txt, key_OTP);
    printf("[OTP] decrypted: %s\n", decipher_txt);


    // ============= CAESARS =============
    int key_caesars;

    printf("[Caesars] input: ");
    fgets(plain,sizeof(plain), stdin);

    printf("[Caesars] key: ");
    scanf("%d", &key_caesars);
    getchar();

    cipher_txt = Caesar_cipher(plain, key_caesars);
    printf("[Caesars] encrypted: %s\n", cipher_txt);

    decipher_txt = Caesar_decipher(cipher_txt, key_caesars);
    printf("[Caesars] decrypted: %s\n", decipher_txt);


    // ============= VIGENERE =============
    
    char key_Vigenere[2048];

    printf("[Vigenere] input: ");
    fgets(plain,sizeof(plain), stdin);

    printf("[Vigenere] key: ");
    fgets(key_Vigenere,sizeof(key_Vigenere), stdin);

    cipher_txt = Vigenere_cipher(plain, key_Vigenere);
    printf("[Vigenere] encrypted: %s\n", cipher_txt);

    decipher_txt = Vigenere_decipher(cipher_txt, key_Vigenere);
    printf("[Vigenere] decrypted: %s\n", decipher_txt);

    return 0;
}
