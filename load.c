#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

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

int main(int argc, char **argv)
{
	int ret = -1;
	struct stat st;
	char *buf = NULL;

	char *module_image = NULL;
	int m_size = 0;
	char *m_params = "";

	if (argc < 1 || argc > 2) {
		fprintf(stderr, "Usage: %s [module_params]\n", argv[0]);
		return 0;
	}

	if (geteuid() != 0)
		return 0;

	if (argc == 2)
		m_params = argv[1];
	
	if (stat(argv[0], &st) < 0)
		goto end;

	buf = malloc(st.st_size);
	if (!buf)
		goto end;
	
	if (read_file(buf, argv[0], st.st_size) < 0)
		goto end;

	module_image = buf+(st.st_size-m_size);
	ret = init_module(module_image, m_size, m_params);
	
end:
	if (buf)
		free(buf);
	return ret;	
}
