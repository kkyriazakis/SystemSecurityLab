#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define MAX_SIZE 4096


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len) {
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len) {
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void) {
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password, int bit_mode, int op_mode) {
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode) {
	if ( bit_mode == 256 ){
		EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, (unsigned char *) password, strlen((char*)password), 1, key, NULL);
	}
    else if ( bit_mode == 128 ){
	    EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, (unsigned char *) password, strlen((char*)password), 1, key, NULL);
    }	
}


/*
 * Encrypts the data
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int bit_mode) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if ( !(ctx = EVP_CIPHER_CTX_new()) ){
        return -1;
    }

	if ( bit_mode == 256 ){
		EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
	}
    else if ( bit_mode == 128 ){
	    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
    }

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int bit_mode) {
	int plaintext_len = 0;
	EVP_CIPHER_CTX *ctx;

    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if ( bit_mode == 256 ){
	    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv) )
        	return -2;
    }
    else if ( bit_mode == 128 ){
	    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv) )
        	return -3;
    }


    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -4;
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len) )
    	return -5;
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *cmac, int bit_mode) {
	CMAC_CTX *ctx = CMAC_CTX_new();
	size_t mactlen;
	
	if ( bit_mode == 256 ){
	    if(1 != CMAC_Init(ctx, key, 32, EVP_aes_256_ecb(), NULL) )
        	return;
    }
    else if ( bit_mode == 128 ){
	    if(1 != CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), NULL) )
        	return;
    }

	CMAC_Update(ctx, data, data_len);

	CMAC_Final(ctx, cmac, &mactlen);

	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2) {
	int verify = 1;
	int i = 0;

	while ( i<16 && verify==1){
		if(cmac1[i] != cmac2[i]){
			verify = 0;
		}
		i++;
	}
	return verify;
}



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);


	// Initialize
	FILE * f;	
	long ciphertext_len = -1, plaintext_len = -1;
	char * plaintext;
	unsigned char *ciphertext;
	unsigned char *key = malloc( bit_mode );


	switch (op_mode) {
		case 0:
			/* =============== encrypt =============== */
			/* Keygen from password */
			keygen(password, key, NULL, bit_mode);

			/* Read plain from file*/
			f = fopen (input_file, "rb");
			if (f) {
				fseek(f, 0, SEEK_END);
				plaintext_len = ftell(f);
				fseek(f, 0, SEEK_SET);
				plaintext = malloc(plaintext_len);
				if (plaintext)
					fread(plaintext, 1, plaintext_len, f);
				fclose (f);
			
				ciphertext = malloc( MAX_SIZE );
				ciphertext_len = encrypt((unsigned char *)plaintext, plaintext_len, key, NULL, ciphertext, bit_mode);

				/* write cipher to file*/
				f = fopen (output_file,"w");
				for(int i = 0; i < ciphertext_len; i++){
					fprintf (f, "%c",ciphertext[i]);
				}
				fclose(f);
			}
			break;


		case 1:
			/* =============== decrypt =============== */
			/* Keygen from password */
			keygen(password, key, NULL, bit_mode);

			f = fopen (input_file, "rb");
			if (f) {
				fseek(f, 0, SEEK_END);
				ciphertext_len = ftell(f);
				fseek(f, 0, SEEK_SET);
				ciphertext = malloc(ciphertext_len);
				if (ciphertext)
					fread(ciphertext, 1, ciphertext_len, f);
				fclose (f);
			
				plaintext = malloc( MAX_SIZE );
				plaintext_len = decrypt(ciphertext, ciphertext_len, key, NULL, (unsigned char *)plaintext, bit_mode);
			
				/* write plain to file*/
				f = fopen (output_file,"w");
				for(int i = 0; i < plaintext_len; i++){
					fprintf (f, "%c",plaintext[i]);
				}
				fclose (f);

			}
			break;


		case 2:
			/* =============== sign =============== */
			/* Keygen from password */
			keygen(password, key, NULL, bit_mode);

			/* Read plain from file*/
			f = fopen (input_file, "rb");
			if (f) {
				fseek(f, 0, SEEK_END);
				plaintext_len = ftell(f);
				fseek(f, 0, SEEK_SET);
				plaintext = malloc(plaintext_len);
				if (plaintext)
					fread(plaintext, 1, plaintext_len, f);
				fclose (f);
			
				ciphertext = malloc( MAX_SIZE );
				ciphertext_len = encrypt((unsigned char *)plaintext, plaintext_len, key, NULL, ciphertext, bit_mode);


				unsigned char *cmac = malloc(16);
				gen_cmac((unsigned char *)plaintext, plaintext_len, key, cmac, bit_mode);

				/* write cipher and cmac to file */ 
				f = fopen (output_file,"w");		
				for(int i = 0; i < 16; i++){
					fprintf (f, "%c",cmac[i]);
				}
				for(int i = 0; i < ciphertext_len; i++){
					fprintf (f, "%c",ciphertext[i]);
				}
				fclose (f);
			}
			break;


		case 3:
			/* =============== verify =============== */
			/* Keygen from password */
			keygen(password, key, NULL, bit_mode);

			/* Read plain from file*/
			f = fopen (input_file, "rb");
			long file_len = -1;
			char * filetext;
			if (f) {
				fseek(f, 0, SEEK_END);
				file_len = ftell(f);
				fseek(f, 0, SEEK_SET);
				filetext = malloc(file_len);
				if (filetext)
					fread(filetext, 1, file_len, f);
				fclose (f);
			
				unsigned char *cmac = malloc(16);
				ciphertext = malloc(file_len - 16);
				ciphertext_len = file_len - 16;
				for(int i=0; i<file_len; i++){
					if (i < 16){
						cmac[i] = filetext[i];
					}
					else{
						ciphertext[i-16] = filetext[i];
					}
				}

				plaintext = malloc( MAX_SIZE );
				plaintext_len = decrypt(ciphertext, ciphertext_len, key, NULL, (unsigned char *)plaintext, bit_mode);

				unsigned char *new_cmac = malloc(16);
				gen_cmac((unsigned char *)plaintext, plaintext_len, key, new_cmac, bit_mode);

				if (verify_cmac(cmac, new_cmac) == 1) {
					printf("cmac verified\n");

					/* write plain to file*/
					f = fopen (output_file,"w");
					for(int i = 0; i < plaintext_len; i++){
						fprintf (f, "%c",plaintext[i]);
					}
					fclose (f);

				}
				else{
					printf("cmac not verified\n");
				}
			}

			break;
	}

	/* Clean up */
	free(key);
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
