#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if ( !(ctx = EVP_CIPHER_CTX_new()) ){
        return -1;
    }
	EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int main(int argc, char *argv[]) {

	FILE *file;
	char *input_file;

	if (argc != 3){
		printf("Arguments required: 2\n");
		return -1;
	}

	int opt;
	while ((opt = getopt(argc, argv, "c:e:")) != -1) {
		switch (opt) {
			case 'c': // CREATE FILE SPECIFIED
				input_file = strdup(optarg);
				file = fopen(input_file, "w+");
				if (file != NULL){
					char *entry;
					asprintf(&entry, "This is the original content of file : %s\n", input_file);
					fwrite(entry, strlen(entry), 1, file);
					fclose(file);
				}

				break;

			case 'e': // ENCRYPT FILE SPECIFIED
				input_file = strdup(optarg);
				file = fopen(input_file, "rb");
				if (file != NULL){
					fseek(file, 0, SEEK_END);
					int plaintext_len = ftell(file);
					fseek(file, 0, SEEK_SET);
					char *plaintext = malloc(plaintext_len);
					if (plaintext)
						fread(plaintext, 1, plaintext_len, file);

					int ciphertext_len;
					unsigned char *ciphertext = malloc( 4096 );;
					ciphertext_len = encrypt((unsigned char *)plaintext, plaintext_len, "2015030086", ciphertext);

					char *enc_title;
					asprintf(&enc_title, "%s.encrypt", input_file);
					FILE *enc_file = fopen(enc_title, "w+");
					if (enc_file != NULL){
						fwrite(ciphertext, ciphertext_len, 1, enc_file);
						fclose(enc_file);
					}
					fclose(file);
				}

			break;

		}
	}
	return 0;
}
