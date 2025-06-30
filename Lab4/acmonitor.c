#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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


int main(int argc, char *argv[]) {
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
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
