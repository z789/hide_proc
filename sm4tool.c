#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sm4.h" 

static int read_file(char *buf, char *fname, int len)
{
	int ret = -1;
	int fd = -1;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		goto end;
	
	ret = read(fd, buf, len);
	if (ret != len) 
		ret = -1;

end:
	if (fd >= 0)
		close(fd);
	return ret;
}

static int write_file(char *buf, char *fname, int len)
{
	int ret = -1;
	int fd = -1;

	fd = open(fname, O_WRONLY|O_TRUNC|O_CREAT, S_IRWXU|S_IRGRP|S_IROTH);
	if (fd < 0)
		goto end;
	
	ret = write(fd, buf, len);
	if (ret != len) 
		ret = -1;

end:
	if (fd >= 0)
		close(fd);
	return ret;
}

int main(int argc, char **argv)
{
	int ret = -1;
	char *key = "123456";
	char *in= NULL;
	char *out = NULL;

	char *buf = NULL;
	struct stat st;
	
	if (argc != 4) {
		fprintf(stderr, "Usage: %s key in_file out_file\n", argv[0]);
		return -1;
	}

	key = argv[1];
	in = argv[2];
	out = argv[3];

	if (stat(in, &st) < 0)
		goto end;

	buf = malloc(st.st_size);
	if (!buf)
		goto end;
	
	if (read_file(buf, in, st.st_size) < 0)
		goto end;

	sm4_encrypt_ctr(buf, st.st_size, key);

	if (write_file(buf, out, st.st_size) < 0)
		goto end;
	ret = 0;

end:
	if (buf)
		free(buf);
	return ret;
}
