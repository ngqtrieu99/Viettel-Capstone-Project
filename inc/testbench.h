#ifndef _TESTBENCH_H
#define _TESTBENCH_H
#include <stdlib.h>
#include <stdint.h>
#include <semaphore.h>
#include <errno.h>

#define INPUT_FILE "testcase/inpTest.txt"

#define handle_error_en(en, msg) \
	do                           \
	{                            \
		errno = en;              \
		perror(msg);             \
		exit(EXIT_FAILURE);      \
	} while (0)

enum testType {
	accuracy = 1,
	speed,
	cpuLoad
};

enum method
{
	SW = 1,
	DPDK
};

enum algo {
    snow3g = 1,
    aes,
    zuc
};

enum type {
	auth = 1,
	cipher,
	both
};

void setAffinity(pthread_t thread_id, int n);
void *DataSendThread(void *vargp);
void *AccuracyCalcThread(void *vargp);
void *ThroughputControlThread(void *vargp);

#endif /* _TESTBENCH_H */
