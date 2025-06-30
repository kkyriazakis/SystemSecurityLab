#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/md5.h>


void getFingerprint(const char *path, unsigned char *c) {
    MD5_CTX mdContext;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *inFile = (*original_fopen)(path, "rb");


    fseek(inFile, 0, SEEK_END);
	int plaintext_len = ftell(inFile);
	fseek(inFile, 0, SEEK_SET);
	char *plaintext = malloc(plaintext_len);
	if (plaintext)
		fread(plaintext, 1, plaintext_len, inFile);

    MD5_Init (&mdContext);
    MD5_Update (&mdContext, plaintext, plaintext_len);    
    MD5_Final (c,&mdContext);

    free(plaintext);
    fclose(inFile);
}


FILE * fopen(const char *path, const char *mode) {
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	unsigned char ftprnt_hex[MD5_DIGEST_LENGTH];
	
	/* Check if File exists or not */
	int access_type;
	if( access( path, F_OK ) != -1 ) {
	    access_type = 1;
	}
	else{
	    access_type = 0;
	}

	/* call the original fopen function */
	original_fopen_ret = (*original_fopen)(path, mode);

	/* Get Uid */
	uid_t uid = getuid();	

	/* Get current date and time and seperate them */
	char date[15];
	char timestamp[10];

	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	strftime(date, sizeof(date), "%d/%m/%Y", t);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", t);

	char fingerprint[33] = "";
	if(access_type == 0)
		strcpy((char*)fingerprint, "00000000000000000000000000000000");
	else{
		/* Get file fingerprint if file exists*/	    
		getFingerprint(path, ftprnt_hex);

		char tmp[3];
		for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
			snprintf(tmp, sizeof(tmp), "%02x", ftprnt_hex[i]);
			strcat(fingerprint, tmp);
		}		
	}

	/* if file pointer is NULL, user has no permission */
	int action_denied;
	if (original_fopen_ret == NULL)
		action_denied = 1;
	else {
		action_denied = 0;
	}



	char *entry;
	asprintf(&entry, "%d-%s-%s-%s-%d-%d-%s\n", uid, path, date, timestamp, access_type, action_denied, fingerprint);
	
	FILE *log = (*original_fopen)("file_logging.log", "a+");
	fputs(entry, log);
	free(entry);
	fclose(log);

	return original_fopen_ret;
}

void getFingerprintWrite(const char *path, const void *ptr, size_t length, char *fingerprint) {
    MD5_CTX mdContext;
    unsigned char c[MD5_DIGEST_LENGTH];
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *inFile = (*original_fopen)(path, "rb");


    fseek(inFile, 0, SEEK_END);
	int plaintext_len = ftell(inFile);
	fseek(inFile, 0, SEEK_SET);
	char *plaintext = malloc(plaintext_len);
	if (plaintext)
		fread(plaintext, 1, plaintext_len, inFile);
	fclose(inFile);

	char *final_text = malloc(plaintext_len + length);
	char *text_towrite = malloc(length);
	memcpy(text_towrite, ptr, length);

	if(plaintext_len > 1){		
		strcpy(final_text, plaintext);
		strcat(final_text, text_towrite);
	}
	else{
		strcpy(final_text, text_towrite);
	}


    MD5_Init(&mdContext);
    MD5_Update(&mdContext, final_text, plaintext_len + length);    
    MD5_Final(c,&mdContext);

    char tmp[3];
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
		snprintf(tmp, sizeof(tmp), "%02x", c[i]);
		strcat(fingerprint, tmp);
	} 
	free(plaintext);
	free(final_text);
	free(text_towrite);   
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");	
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	int access_type = 2;

	/* Get Uid */
	uid_t uid = getuid();	

	/* Get current date and time and seperate them */
	char date[15];
	char timestamp[10];

	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	strftime(date, sizeof(date), "%d/%m/%Y", t);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", t);


    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    char filename[0xFFF];
    int fno;
    ssize_t r;

    fno = fileno(stream);
    sprintf(proclnk, "/proc/self/fd/%d", fno);
    r = readlink(proclnk, filename, MAXSIZE);
    if (r < 0) {
        printf("failed to readlink\n");
        exit(1);
    }
    filename[r] = '\0';
    char path[32];
    strcpy(path, basename(filename));

    char fingerprint[33] = "";
	getFingerprintWrite(path, ptr, size*nmemb, fingerprint);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	int action_denied = 0;
	if(original_fwrite_ret != nmemb)
		action_denied = 1;

	char *entry;
	asprintf(&entry, "%d-%s-%s-%s-%d-%d-%s\n", uid, path, date, timestamp, access_type, action_denied, fingerprint);

	FILE *log = (*original_fopen)("file_logging.log", "a+");
	fputs(entry, log);
	free(entry);
	fclose(log);


	return original_fwrite_ret;
}


