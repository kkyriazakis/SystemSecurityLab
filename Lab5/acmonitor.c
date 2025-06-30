#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *date; /* file access date */
	char *time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

};


void usage(void) {
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-v <number of files>, Prints the total number of files created in the last 20 minutes\n"
		   "-e <filename>, Prints all the files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


struct entry **AnalyzeLogFile(char *text, int *entry_size) {
	char *data;
	struct tm *t;
	const char del[2] = "\n-";

	int entry_count = 0;
	int data_count = 0;

	struct entry **entry_array = NULL;
	entry_array = (struct entry **)realloc(entry_array, (entry_count + 1) * sizeof(struct entry *));
	entry_array[entry_count] = (struct entry *)malloc(sizeof(struct entry));
	
	data = strtok(text, del);
	while( data != NULL ) {
		switch(data_count){
			case 0:	//uid
					entry_array[entry_count]->uid = atoi(data);
					break;

			case 1: //file name
					entry_array[entry_count]->file = malloc( strlen(data) + 1 );
					strcpy(entry_array[entry_count]->file, data);
					break;

			case 2: //Date
					entry_array[entry_count]->date = malloc( strlen(data) + 1 );
					strcpy(entry_array[entry_count]->date, data);
					break;

			case 3:	//Time
					entry_array[entry_count]->time = malloc( strlen(data) + 1 );
					strcpy(entry_array[entry_count]->time, data);			
					break;

			case 4:	//Access type
					entry_array[entry_count]->access_type = atoi(data);
					break;

			case 5:	//Action Denied flag
					entry_array[entry_count]->action_denied = atoi(data);
					break;

			case 6: //File Fingerprint
					entry_array[entry_count]->fingerprint = malloc( strlen(data) + 1 );
					strcpy(entry_array[entry_count]->fingerprint, data);
					break;
		}
		if(data_count == 6){
			entry_count++;
			entry_array = (struct entry **)realloc(entry_array, (entry_count + 1) * sizeof(struct entry *));
			entry_array[entry_count] = (struct entry *)malloc(sizeof(struct entry));
			data_count = 0;
		}
		else	
			data_count++;
		data = strtok(NULL, del);
	}
	*entry_size = entry_count;

	return entry_array;
}


void list_unauthorized_accesses(FILE *log) {
	int text_len;
	char *text;

	//Read file contents
	fseek(log, 0, SEEK_END);
	text_len = ftell(log);
	fseek(log, 0, SEEK_SET);
	text = malloc(text_len);
	fread(text, 1, text_len, log);
	if (text_len < 1)
		return;

	struct entry **entry_array;
	int entry_size;
	entry_array = AnalyzeLogFile(text, &entry_size);
	free(text);

	int visited[entry_size];
	for(int i=0; i<entry_size; i++){
		visited[i] = 0;
	}
	char **violations = NULL;
	int violation_num = 0;

	for(int i=0; i<entry_size; i++){
		if(visited[i] == 0){
			visited[i] = 1;
			int uid = entry_array[i]->uid;
			
			//Find and Store all violations for current uid
			for(int j=i; j<entry_size; j++){
				if ( entry_array[j]->uid == uid ){
					visited[j] = 1;
					if( entry_array[j]->action_denied == 1 ){
						violation_num++;
						violations = realloc(violations, violation_num * sizeof(char*));	
						
						violations[ violation_num-1 ] = malloc( strlen(entry_array[j]->file) );
						strcpy( violations[ violation_num-1 ] , entry_array[j]->file);
					}
				}
			}

			if(violation_num > 7){
				//Count Different file violations
				int unique_count = 0;
				int x,y;
				for (x = 0; x < violation_num; x++) {
	    			for (y = x + 1; y < violation_num; y++)
	        			if (strcmp(violations[x], violations[y]) == 0)
	            			break;
	    			if (y == violation_num)
	        			unique_count++;
				}
				if(unique_count > 7)
					printf("malicious User : %d\n", uid);
			}
		}
	}

	return;
}


void list_file_modifications(FILE *log, char *file_to_scan) {
	int text_len;
	char *text;

	//Read LOG file contents
	fseek(log, 0, SEEK_END);
	text_len = ftell(log);
	fseek(log, 0, SEEK_SET);
	text = malloc(text_len);
	fread(text, 1, text_len, log);
	if (text_len <= 1){
		printf("log file is empty\n");
		return;
	}

	struct entry **entry_array;
	int entry_size;
	entry_array = AnalyzeLogFile(text, &entry_size);

	char fingerprint[entry_size][33];
	int user[entry_size];
	int visited[entry_size];
	int arr_size = 0;
	for(int i=0; i<entry_size; i++){
		visited[i] = 0;
		if( strcmp(entry_array[i]->file, file_to_scan) == 0 ){
			user[arr_size] = entry_array[i]->uid;
			strncpy(fingerprint[arr_size], entry_array[i]->fingerprint, 33);
			arr_size++;
		}
	}

	for(int i=0; i<arr_size; i++){
		int curr_uid = user[i];
		char curr_modifications[arr_size][33];
		int mod_count = 0;

		if(visited[i] == 1)
			continue;

		for(int j=i; j<arr_size; j++){
			if( user[j] == curr_uid){
				visited[j] = 1;
				strncpy(curr_modifications[mod_count], fingerprint[j], 33);				
				mod_count++;
			}
		}
		int unique_count = 0;
		int x,y;
		for (x = 0; x < mod_count; x++) {
			for (y = x + 1; y < mod_count; y++)
    			if (strcmp(curr_modifications[x], curr_modifications[y]) == 0)
        			break;
			if (y == mod_count)
    			unique_count++;
		}
		printf("User %d, modified file %s, %d times\n", curr_uid, file_to_scan, unique_count);

	}

	return;

}


int get_last20min_files(FILE *log) {
	int count = 0;
	int text_len;
	char *text;

	//Read file contents
	fseek(log, 0, SEEK_END);
	text_len = ftell(log);
	fseek(log, 0, SEEK_SET);
	text = malloc(text_len);
	fread(text, 1, text_len, log);
	if (text_len < 1)
		return 0;

	struct entry **entry_array;
	int entry_size;
	entry_array = AnalyzeLogFile(text, &entry_size);
	free(text);

	for(int e=0; e<entry_size; e++){
		if( entry_array[e]->access_type == 0 ){ //FILE CREATION
			time_t now = time(NULL);	

			char *time_details;
			asprintf(&time_details, "%s %s", entry_array[e]->date, entry_array[e]->time);
			struct tm tm;
			strptime(time_details, "%d/%m/%Y %H:%M:%S", &tm);
			time_t creation = mktime(&tm);  // t is now your desired time_t	

			double time_diff = difftime(now, creation);

			if(time_diff <= 1200) //less than 20 minutes
				count++;
		}
	}
	return count;
}

void find_ransomware(FILE *log) {
	int text_len;
	char *text;

	//Read file contents
	fseek(log, 0, SEEK_END);
	text_len = ftell(log);
	fseek(log, 0, SEEK_SET);
	text = malloc(text_len);
	fread(text, 1, text_len, log);
	if (text_len < 1)
		return;

	struct entry **entry_array;
	int entry_size;
	entry_array = AnalyzeLogFile(text, &entry_size);
	free(text);

	char suffix[9] = ".encrypt";
	for(int e=0; e<entry_size; e++){
		if( entry_array[e]->access_type == 0 && strlen(entry_array[e]->file) > 8 ){ 

			if( strcmp(entry_array[e]->file+strlen(entry_array[e]->file)-8, suffix) == 0 ){
				printf("File ");
				for(int i=0; i<strlen(entry_array[e]->file)-8; i++)
					printf("%c", (entry_array[e]->file)[i] );
				printf(" was encrypted by the ransomware\n");
			}			
		}
	}
	return;
}


int main(int argc, char *argv[]) {
	int ch;
	FILE *log;
	int num_files;
	int count;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m:v:e")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			num_files = atoi(optarg);
			count = get_last20min_files(log);
			
			if(count < num_files)
				printf("Total number of created files in the last 20 minutes: %d\n", count);
			else
				printf("Nothing suspicious found\n");

			break;
		case 'e':
			find_ransomware(log);
			break;
		default:
			usage();
		}

	}


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
