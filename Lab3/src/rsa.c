#include "rsa.h"
#include "utils.h"
#include <math.h> 

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit */
size_t *sieve_of_eratosthenes(int limit, int *primes_sz) {
	size_t *primes;
	int i, j, ctr;

	//populating array with naturals numbers
	int prime_temp[limit + 1];
	for(i = 0; i<=limit; i++)
		prime_temp[i] = i;

	ctr = limit;
	i = 2;
	while( (i*i) <= limit) {
		if (prime_temp[i] != 0) {
			for(j=2; j<limit; j++) {
				if (prime_temp[i]*j > limit)
					break;
				else
					prime_temp[ prime_temp[i]*j ] = 0; // Mark As Non-Prime
			}
		}
		i++;
    }

    *primes_sz = 0;
	for(i = 2; i<=limit; i++) {
		if (prime_temp[i] != 0)		
			*primes_sz += 1;
	}

    primes = malloc( (*primes_sz) * sizeof(size_t) );
    ctr = 0;
	for(i = 2; i<=limit; i++) {
		//If number is not 0 then it is prime
		if (prime_temp[i] != 0){			
			primes[ctr++] = prime_temp[i];
		}
	}

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int gcd(int a, int b) {
	int gcd;
	for(int i=1; i <= a && i <= b; ++i) {
		if(a%i == 0 && b%i == 0) // Checks if i is factor of both integers
			gcd = i;
	}
	return gcd;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n) {
	size_t e;

	int primes_sz;
	size_t* primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);

	for(int i=0; i<primes_sz; i++){
		e = primes[i];
		if( (e % fi_n != 0) & (gcd(e, fi_n) == 1) )
			return e;
	}
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t mod_inverse(size_t a, size_t b) {
	a = a%b; 
	for(int x=1; x<b; x++) 
		if( (a*x) % b == 1 )
			return x; 

	return 0;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void) {
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	int primes_sz;
	size_t* primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);

	/* Intializes random number generator */
	time_t t;
	srand((unsigned) time(&t));

	p = primes[ rand() % primes_sz ];
	q = primes[ rand() % primes_sz ];

	n = p * q;
	fi_n = (p-1)*(q-1);

	e = choose_e(fi_n);
	d = mod_inverse(e,fi_n);

	FILE *public = fopen("public.key", "wb");
	FILE *private = fopen("private.key", "wb");

	if (public == NULL || private == NULL) {
		printf("Error creating .key files...\n"); 
		return;
	}
	
	fwrite(&n, sizeof(size_t), 1, public);
	fwrite(&d, sizeof(size_t), 1, public);

	fwrite(&n, sizeof(size_t), 1, private);
	fwrite(&e, sizeof(size_t), 1, private);

	fclose(public);
	fclose(private);
}


// returns (a^b)mod n
int modulo(int a, int b, int n){
	long long x=1, y=a; 
	while (b > 0) {
		if (b%2 == 1) {
			x = (x*y) % n; // multiplying with base
		}
		y = (y*y) % n; // squaring the base
		b /= 2;
    }
    return x % n;
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *input_file, char *output_file, char *key_file) {
	FILE *key = fopen(key_file, "rb");
	FILE *input = fopen(input_file, "rb");

	if (key == NULL || input == NULL) {
		printf("Error opening files...\n"); 
		return;
	}

	// READ DATA FROM KEY FILE
	size_t n, pwr;
	fread(&n, sizeof(size_t), 1, key);
	fread(&pwr, sizeof(size_t), 1, key);
	fclose(key);

	// READ DATA FROM INPUT FILE
	char *plaintext;
	int plaintext_len;

	fseek(input, 0, SEEK_END);
	plaintext_len = ftell(input);
	fseek(input, 0, SEEK_SET);
	plaintext = malloc(plaintext_len);
	if (plaintext)
		fread(plaintext, 1, plaintext_len, input);
	fclose(input);

	
	// WRITE DATA TO OUTPUT FILE
	FILE *out = fopen(output_file, "wb");
	if (out == NULL) {
		printf("Error creating output file...\n"); 
		return;
	}
	int mod = (double)n;
	size_t power;
	size_t cipher;
	for(int i = 0; i < plaintext_len; i++){
		cipher = (size_t)modulo(plaintext[i], pwr, mod);
		fwrite(&cipher, sizeof(size_t), 1, out);
	}
	fclose(out);



}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *input_file, char *output_file, char *key_file) {
	FILE *key = fopen(key_file, "rb");
	FILE *input = fopen(input_file, "rb");

	if (key == NULL || input == NULL) {
		printf("Error opening files...\n"); 
		return;
	}

	// READ DATA FROM KEY FILE
	size_t n, pwr;
	fread(&n, sizeof(size_t), 1, key);
	fread(&pwr, sizeof(size_t), 1, key);
	fclose(key);

	// READ DATA FROM INPUT FILE
	size_t *ciphertext;
	int ciphertext_len;

	fseek(input, 0, SEEK_END);
	ciphertext_len = ftell(input);
	fseek(input, 0, SEEK_SET);
	ciphertext = malloc(ciphertext_len);
	if (ciphertext)
		fread(ciphertext, sizeof(size_t), ciphertext_len, input);
	fclose(input);

	// DECRYPT AND WRITE DATA TO OUTPUT FILE
	int plaintext_len = ciphertext_len/8;
	char *plaintext = malloc(ciphertext_len/8);
	size_t power;
	for(int i = 0; i < plaintext_len; i++){
		plaintext[i] = (size_t)modulo(ciphertext[i], pwr, n);
	}

	FILE *out = fopen(output_file, "w");
	if (out == NULL) {
		printf("Error creating output file...\n"); 
		return;
	}
	for(int i = 0; i < plaintext_len; i++){
		fprintf (out, "%c",plaintext[i]);
	}
	fclose(out);
}
