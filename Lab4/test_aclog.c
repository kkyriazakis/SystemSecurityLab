#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */	
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	
	file = fopen(filenames[0], "a+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite("", strlen(""), 1, file);
		bytes = fwrite("test", strlen("test"), 1, file);
		bytes = fwrite("1", strlen("1"), 1, file);
		fclose(file);
	}


	char cmd[32];
	for (i = 0; i < 10; i++) {
		sprintf(cmd, "chmod 400 %s", filenames[i]);
		system(cmd);

		file = fopen(filenames[i], "w");
		if (file != NULL) {
			fwrite("No Permission Message", strlen("No Permission Message"), 1, file);
			fclose(file);
		}

		sprintf(cmd, "chmod 755 %s", filenames[i]);
		system(cmd);		
	
	}


}
