#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>


int main(void)
{
	fprintf(stdout, "pid:%d\n", getpid());
	sleep(1000);
	return 0;
}
