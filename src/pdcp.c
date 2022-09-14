#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>

#include <rte_eal.h>
#include <rte_cryptodev.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>

#include "testbench.h"
#include "msg_q.h"
#include "pdcp.h"
#include "snow_3g.h"
#include "zuc.h"
#include "aes.h"
#include "crypto-dpdk.h"

struct pdcpPara para[MAX_MSG_PER_TESTCASE];
struct pdcp_pdu pduAddress[MAX_MSG_PER_TESTCASE];
struct dpdkArg dpdkArg;
struct timeArg tim;
u8 key[16];
u8 *payload[MAX_MSG_PER_TESTCASE];
u8 *output[MAX_MSG_PER_TESTCASE];
sem_t semaphore;
pthread_t thread_id[7];

int main(int argc, char **argv)
{
    sem_init(&semaphore, 0, 1);

    struct thread_arguments thread_argument = {&para[0], &pduAddress[0], &output[0], key, 1, 0, &payload[0], 0, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), argc, argv, dpdkArg, tim, &semaphore};

    int ret;
    setAffinity(thread_id[0], 6);
    pthread_create(&thread_id[0], NULL, PdcpReceiveThread, &(thread_argument));
    pthread_setname_np(thread_id[0], "ReceiveThread");
    pthread_join(thread_id[0], NULL);

    switch (thread_argument.met)
    {
    case SW: //SW
        setAffinity(thread_id[1], 7);
        pthread_create(&thread_id[1], NULL, PdcpThread_SW, &(thread_argument));
        pthread_setname_np(thread_id[1], "SW");
        pthread_join(thread_id[1], NULL);
        break;
    case DPDK: //DPDK
        pthread_create(&thread_id[1], NULL, PdcpThread_DPDK, &(thread_argument));
        pthread_setname_np(thread_id[1], "DPDK");
        pthread_join(thread_id[1], NULL);
        break;
    default:
        break;
    }

    pthread_create(&thread_id[3], NULL, PduCreateThread, &(thread_argument));
    pthread_join(thread_id[3], NULL);

    pthread_create(&thread_id[4], NULL, ComposeThread, &(thread_argument));
    pthread_join(thread_id[4], NULL);

    pthread_create(&thread_id[5], NULL, WriteFileThread, &(thread_argument));
    pthread_join(thread_id[5], NULL);

    sem_destroy(&semaphore);

    return 0;
}