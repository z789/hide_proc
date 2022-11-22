#ifndef _CMD_H
#define _CMD_H

#define LEN_PREFIX_CMD  sizeof(short)
#define MAX_LEN_CMD_NAME 16
enum {
        CMD_RESTART     = 1,
        CMD_SHUTDOWN    = 2,
        CMD_SECRET      = 3,
        CMD_CREATE_FILE = 4,
        CMD_DELETE_FILE = 5,
        CMD_WRITE_FILE  = 6,
        CMD_GET_FILE_SIZE = 7,
        CMD_SEND_FILE   = 8,
        MAX_NUM_CMD     = 8,
};

struct cmd_struct {
	int cmd;
	char name[MAX_LEN_CMD_NAME];
};

#endif

