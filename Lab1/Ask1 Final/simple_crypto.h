#ifndef ASK1_LIBRARY_SIMPLE_CRYPTO_H
#define ASK1_LIBRARY_SIMPLE_CRYPTO_H

#define N 50
#define KEY_SIZE 512

char* OTP_cipher(char* plain_txt, char* key);
char* OTP_decipher(char* cipher_txt, char* key);

char* Caesar_cipher(char* plain_txt, int key);
char* Caesar_decipher(char* cipher_txt, int key);

char* Vigenere_cipher(char *plain_txt, char *key);
char* Vigenere_decipher(char *cipher_txt, char *key);

#endif //ASK1_LIBRARY_SIMPLE_CRYPTO_H
