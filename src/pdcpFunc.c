#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>

#include <rte_bus_vdev.h>
#include <rte_eal.h>
#include <rte_cryptodev.h>
#include <rte_mempool.h>

#include "testbench.h"
#include "msg_q.h"
#include "pdcp.h"
#include "snow_3g.h"
#include "zuc.h"
#include "aes.h"
#include "crypto-dpdk.h"

// void parse_msg(u8* byte, size_t data_length, size_t maci_length)
// {

// 	pdu *parse;
// 	parse->DC_field=(byte[0] >> 7) & 0xFF;
// 	parse->sqnum = ((byte[0] << 8) & 0xF00) + byte[1];
// 	parse->byteData.data = 0;
// 	parse->maci = 0;
// 	int i=0;
// 	for(; i<data_length; i++)
// 		parse->byteData.data += byte[i+2] << (8*(data_length-i-1));
// 	for(; i<(data_length+maci_length); i++)
// 		parse->maci += byte[i+2] << (8*(data_length+maci_length-i-1));
// }

void compose(struct pdcp_pdu *compose, u8 *byte, u32 *length)
{
    // declare byte array
    byte[0] = (compose->DC_field << 7) & 0xff | (compose->sqnum >> 16) & 0xff; // a number shift to the left 7 bits
    byte[1] = (compose->sqnum >> 8) & 0xff;
    byte[2] = (compose->sqnum) & 0xff;
    int byteOrder = 3;
    int loop = compose->length;

    for (int i = 0; i < loop; i++)
    {
        byte[byteOrder] = (compose->data[i]) & 0xff;
        byteOrder++;
    }
    for (int i = 0; i < 4; i++)
    {
        byte[byteOrder] = (compose->maci[i]) & 0xff;
        byteOrder++;
    }
    *length = compose->length + 7;
}

void getPayload(char *arg, struct pdcpPara *para)
{
    char res[MAX_MSG_LEN];
    const char *p = arg;
    int i = 0;
    int check = 0;
    int k = 0;
    int count;
    while (1)
    {
        if (check == 1)
        {
            break;
        }
        switch (*(p + k))
        {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            res[i] = *(p + k) - '0';
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            res[i] = *(p + k) - 'A' + 10;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            res[i] = *(p + k) - 'a' + 10;
            break;
        default:
            check = 1;
            count = k;
            break;
        }
        k++;
        if (check == 1)
        {
            break;
        }
        switch (*(p + k))
        {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            res[i] = res[i] * 16 + *(p + k) - '0';
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            res[i] = res[i] * 16 + *(p + k) - 'A' + 10;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            res[i] = res[i] * 16 + *(p + k) - 'a' + 10;
            break;
        default:
            check = 1;
            count = k;
            res[i] = res[i] << 4;
        }
        k++;
        i++;
    }

    int t = count / 2 + count % 2;
    para->length = 8 * t;
    // para->payload = (u8 *)cp_mempool_alloc(mempool);
    for (int j = 0; j < t; j++)
    {
        para->payload[j] = 0xFF & res[j];
    }
}
void getKey(char *arg, struct thread_arguments *args)
{
    char res[MAX_MSG_LEN];
    const char *p = arg;
    int i = 0;
    int check = 0;
    int k = 0;
    int count;
    while (1)
    {
        if (check == 1)
        {
            break;
        }
        switch (*(p + k))
        {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            res[i] = *(p + k) - '0';
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            res[i] = *(p + k) - 'A' + 10;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            res[i] = *(p + k) - 'a' + 10;
            break;
        default:
            check = 1;
            count = k;
            break;
        }
        k++;
        if (check == 1)
        {
            break;
        }
        switch (*(p + k))
        {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            res[i] = res[i] * 16 + *(p + k) - '0';
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            res[i] = res[i] * 16 + *(p + k) - 'A' + 10;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            res[i] = res[i] * 16 + *(p + k) - 'a' + 10;
            break;
        default:
            check = 1;
            count = k;
            res[i] = res[i] << 4;
        }
        k++;
        i++;
    }
    int t = count / 2 + count % 2;
    //    para->key = (u8 *)malloc(t);
    for (int j = 0; j < t; j++)
    {
        args->key[j] = 0xFF & res[j];
    }
}

void timeCalc(struct timeArg *timePtr)
{
    timePtr->processTimePerLoop = (double)(timePtr->stop - timePtr->start) / CLOCKS_PER_SEC;
    timePtr->processTime += timePtr->processTimePerLoop;
    timePtr->totalLength += timePtr->length;
}

void printHeader(struct thread_arguments *args)
{
    switch (args->algo)
    {
    case snow3g:
        printf("\nSNOW3G ");
        break;
    case aes:
        printf("\nAES ");
        break;
    case zuc:
        printf("\nZUC ");
    default:
        break;
    }

    switch (args->met)
    {
    case SW:
        printf("SW\n");
        break;
    case DPDK:
        printf("DPDK\n");
        break;
    default:
        break;
    }

    if (args->param == speed)
        printf("\nTotal Data: %.3fMB\n", (args->countRow * 1500.0) / (1024.0 * 1024));

    printf("\nTotal Length (MB)\tProcess Time (s)\tAvgSpeed (MBps)\n");
}

void showTime(struct timeArg *timePtr)
{
    printf("%.3lf\t\t\t%.3lf\t\t\t%.3lf\n", timePtr->totalLength / (1024.0 * 1024), timePtr->processTime, ((double)timePtr->totalLength / (1024.0 * 1024)) / timePtr->processTime);
}

void swProcess(struct thread_arguments *args, struct pdcpPara *myid, int i)
{
    switch (args->algo)
    {
    case snow3g:
        if (args->type == auth || args->type == both)
            snow_3g_integrity(args->key, myid[i].count, myid[i].bearer, myid[i].dir, myid[i].length, myid[i].payload, myid[i].mac);
        if (args->type == cipher || args->type == both)
            snow_3g_ciphering(args->key, myid[i].count, myid[i].bearer, myid[i].dir, myid[i].length, myid[i].payload, myid[i].cipher);
        break;
    case aes:
        if (args->type == auth || args->type == both)
            aes_cmac_integrity(args->key, myid[i].count, myid[i].bearer, myid[i].dir, myid[i].length, myid[i].payload, myid[i].mac);
        if (args->type == cipher || args->type == both)
            aes_ctr_ciphering(args->key, myid[i].count, myid[i].bearer, myid[i].dir, myid[i].length, myid[i].payload, myid[i].cipher);
        break;
    case zuc:
        if (args->type == auth || args->type == both)
            zuc_integrity(args->key, myid[i].count, myid[i].bearer, myid[i].dir, myid[i].length, myid[i].payload, myid[i].mac);
        if (args->type == cipher || args->type == both)
            zuc_ciphering(args->key, myid[i].count, myid[i].bearer, myid[i].dir, myid[i].length, myid[i].payload, myid[i].cipher);
        break;
    default:
        break;
    }
}

void initDpdk(struct dpdkArg *arg, int argc, char **argv, u8 *key, u8 algo)
{
    int ret;

    /* Initialize EAL. */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

    /* Create the virtual crypto device. */
    const char *crypto_name = "crypto_aesni_mb";
    ret = rte_vdev_init(crypto_name, NULL);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "Cannot create virtual device\n");

    arg->cdev_id = rte_cryptodev_get_dev_id(crypto_name);
    arg->socket_id = rte_socket_id();

    /* Create the mbuf pool. */
    arg->mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
                                             NUM_MBUFS,
                                             POOL_CACHE_SIZE,
                                             0,
                                             RTE_MBUF_DEFAULT_BUF_SIZE,
                                             arg->socket_id);
    if (arg->mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /*
     * The IV is always placed after the crypto operation,
     * so some private data is required to be reserved.
     */
    unsigned int crypto_op_private_data = IV_LENGTH;

    /* Create crypto operation pool. */
    arg->crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
                                                    RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                                    NUM_MBUFS,
                                                    POOL_CACHE_SIZE,
                                                    crypto_op_private_data,
                                                    arg->socket_id);
    if (arg->crypto_op_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create crypto op pool\n");

    /* Get private session data size. */
    unsigned int session_size = rte_cryptodev_sym_get_private_session_size(arg->cdev_id);

    /* Use of the same mempool for session header and private data */
    arg->session_pool = rte_cryptodev_sym_session_pool_create("session_pool",
                                                              MAX_SESSIONS * 2,
                                                              session_size,
                                                              POOL_CACHE_SIZE,
                                                              0,
                                                              arg->socket_id);

    arg->session_priv_pool = arg->session_pool;

    /* Configure the crypto device. */
    struct rte_cryptodev_config conf = {
        .nb_queue_pairs = 1,
        .socket_id = arg->socket_id};

    struct rte_cryptodev_qp_conf qp_conf = {
        .nb_descriptors = 2048,
        .mp_session = arg->session_pool,
        .mp_session_private = arg->session_priv_pool};

    if (rte_cryptodev_configure(arg->cdev_id, &conf) < 0)
        rte_exit(EXIT_FAILURE, "Failed to configure cryptodev %u\n", arg->cdev_id);

    if (rte_cryptodev_queue_pair_setup(arg->cdev_id, 0, &qp_conf, arg->socket_id) < 0)
        rte_exit(EXIT_FAILURE, "Failed to setup queue pair\n");

    if (rte_cryptodev_start(arg->cdev_id) < 0)
        rte_exit(EXIT_FAILURE, "Failed to start device\n");

    for (int i = 0; i < 2; i++)
    {
        arg->session[i] = rte_cryptodev_sym_session_create(arg->session_pool);
        if (arg->session[i] == NULL)
            rte_exit(EXIT_FAILURE, "Session could not be created\n");
    }

    struct rte_crypto_sym_xform auth_xform = {
        .next = NULL,
        .type = RTE_CRYPTO_SYM_XFORM_AUTH,
        .auth = {
            .op = RTE_CRYPTO_AUTH_OP_GENERATE,
            .key = {
                .data = key,
                .length = KEY_LENGTH},
            .iv = {.offset = IV_OFFSET, .length = IV_LENGTH},
            .digest_length = DIGEST_LENGTH}};

    switch (algo)
    {
    case snow3g:
        auth_xform.auth.algo = RTE_CRYPTO_AUTH_SNOW3G_UIA2;
        break;
    case aes:
        auth_xform.auth.algo = RTE_CRYPTO_AUTH_AES_CMAC;
        break;
    case zuc:
        auth_xform.auth.algo = RTE_CRYPTO_AUTH_ZUC_EIA3;
        break;
    default:
        break;
    }

    if (rte_cryptodev_sym_session_init(arg->cdev_id, arg->session[0], &auth_xform, arg->session_priv_pool) < 0)
        rte_exit(EXIT_FAILURE, "Session could not be initialized for the crypto device\n");

    struct rte_crypto_sym_xform cipher_xform = {
        .next = NULL,
        .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
        .cipher = {
            .op = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
            .key = {
                .data = key,
                .length = KEY_LENGTH},
            .iv = {.offset = IV_OFFSET, .length = IV_LENGTH}}};

    switch (algo)
    {
    case snow3g:
        cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_SNOW3G_UEA2;
        break;
    case aes:
        cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_AES_CTR;
        break;
    case zuc:
        cipher_xform.cipher.algo = RTE_CRYPTO_CIPHER_ZUC_EEA3;
        break;
    default:
        break;
    }

    if (rte_cryptodev_sym_session_init(arg->cdev_id, arg->session[1], &cipher_xform, arg->session_priv_pool) < 0)
        rte_exit(EXIT_FAILURE, "Session could not be initialized for the crypto device\n");
}

void dpdkAlloc(struct dpdkArg *arg, u16 alloc_count)
{
    if ((arg->crypto_ops[alloc_count] = rte_crypto_op_alloc(arg->crypto_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC)) == NULL)
        rte_exit(EXIT_FAILURE, "Not enough crypto operations available\n");

    if ((arg->mbufs[alloc_count] = rte_pktmbuf_alloc(arg->mbuf_pool)) == NULL)
        rte_exit(EXIT_FAILURE, "Not enough mbufs available\n");
}

void dpdkFree(struct dpdkArg *arg, u16 free_count)
{
    rte_pktmbuf_free(arg->mbufs[free_count]);
    rte_crypto_op_free(arg->crypto_ops[free_count]);
}

void dpdkCryptodevStop(struct dpdkArg *arg)
{
    for (int i = 0; i < 2; i++)
    {
        if (rte_cryptodev_sym_session_clear(arg->cdev_id, arg->session[i]))
            rte_exit(EXIT_FAILURE, "Session could not be cleared\n");
        if (rte_cryptodev_sym_session_free(arg->session[i]))
            rte_exit(EXIT_FAILURE, "Session could not be freed\n");
    }
    rte_cryptodev_stop(arg->cdev_id);

    rte_mempool_free(arg->session_priv_pool);
    rte_mempool_free(arg->session_pool);
    rte_mempool_free(arg->crypto_op_pool);
    rte_mempool_free(arg->mbuf_pool);
}

void setAffinity(pthread_t thread_id, int n)
{
    cpu_set_t cpuset;

    thread_id = pthread_self();

    CPU_ZERO(&cpuset);
    CPU_SET(n, &cpuset);

    int ret = pthread_setaffinity_np(thread_id, sizeof(cpuset), &cpuset);
    if (ret != 0)
        handle_error_en(ret, "pthread_setaffinity_np");
}

void *PdcpReceiveThread(void *vargp)
{
    struct thread_arguments *args = (struct thread_arguments *)vargp;
    u8 *key = (u8 *)args->key;
    struct pdcpPara *para = (struct pdcpPara *)args->para_ptr;
    u8 **payload = (u8 **)args->payload;
    // cp_mempool *mempool = cp_mempool_create_by_option(0, 1500, 75000);
    // key = "AC21201963BDCAE152201EFAA2601999";
    u64 i = 0;
    u8 t = 1, loop = 0;
    char text[3000];

    sem_wait(args->semaphore);
    getKey("AC21201963BDCAE152201EFAA2601999", args);
    // for (int j = 0; j < 16; j++)
    //     printf("0x%02x ", args->key[j]);
    printf("\n");
    while (1)
    {
        if (t == 0)
            t = 1;
        read_msg_q(text, t);
        // printf("%ld\n", strlen(text));
        if (strlen(text) == 0)
        {
            printf("%ld\n", args->countRow);
            break;
        }
        // getKey(key, &para[args->countRow]);
        para[args->countRow].bearer = 0x15;
        para[args->countRow].dir = 0x0;
        payload[args->countRow] = &text[0];
        getPayload(payload[args->countRow], &para[args->countRow]);
        args->totalLength += para[args->countRow].length;
        para[args->countRow].count = args->countRow + 1;
        args->countRow++;
        t++;
    }

    sem_post(args->semaphore);
    pthread_exit(NULL);
}

void *PdcpThread_SW(void *vargp)
{
    struct thread_arguments *args = (struct thread_arguments *)vargp;
    struct pdcpPara *myid = (struct pdcpPara *)args->para_ptr;
    struct timeArg *time = &(args->timArg);
    u64 swCountRow = 0;
    u8 algorithm = args->algo;
    u8 loop = 1;
    time->length = 1500;

    sem_wait(args->semaphore);
    if (args->param == accuracy)
    {
        while (swCountRow < args->countRow)
        {
            swProcess(args, myid, swCountRow);
            swCountRow++;
        }
    }
    else
    {
        printHeader(args);
        while (1)
        {
            if (loop % 3 == 0)
                showTime(time);
            while (swCountRow < args->countRow)
            {
                time->start = clock();
                swProcess(args, myid, swCountRow);
                time->stop = clock();
                timeCalc(time);
                swCountRow++;
            }
            loop++;
            swCountRow = 0;
        }
    }

    sem_post(args->semaphore);
    pthread_exit(NULL);
}

void *PdcpThread_DPDK(void *vargp)
{
    struct thread_arguments *args = (struct thread_arguments *)vargp;
    struct pdcpPara *myid = (struct pdcpPara *)args->para_ptr;
    struct dpdkArg arg = args->dpdkArg;
    struct timeArg *time = &(args->timArg);
    time->length = 1500;
    u64 dpdkCountRow = 0;
    u32 alloc_count = 0, free_count = 0, start_free = 0;

    sem_wait(args->semaphore);
    initDpdk(&arg, args->argc, args->argv, args->key, args->algo);

    if (args->param == accuracy)
    {
        while (dpdkCountRow < args->countRow)
        {
            if (args->type == auth || args->type == both)
            {
                if (start_free)
                {
                    dpdkFree(&arg, free_count);
                    free_count++;
                }
                dpdkAlloc(&arg, alloc_count);
                dpdkIntegrity(args->algo, arg.cdev_id, arg.session[0], arg.crypto_ops[alloc_count], arg.mbufs[alloc_count], myid[dpdkCountRow].count, myid[dpdkCountRow].bearer, myid[dpdkCountRow].dir, (myid[dpdkCountRow].length + 7) / 8, myid[dpdkCountRow].payload, myid[dpdkCountRow].mac);
                alloc_count++;
                if (alloc_count == NUM_MBUFS)
                {
                    start_free = 1;
                    alloc_count = 0;
                    free_count = 0;
                }
            }
            if (args->type == cipher || args->type == both)
            {
                if (start_free)
                {
                    dpdkFree(&arg, free_count);
                    free_count++;
                }
                dpdkAlloc(&arg, alloc_count);
                dpdkCiphering(args->algo, arg.cdev_id, arg.session[1], arg.crypto_ops[alloc_count], arg.mbufs[alloc_count], myid[dpdkCountRow].count, myid[dpdkCountRow].bearer, myid[dpdkCountRow].dir, (myid[dpdkCountRow].length + 7) / 8, (u8)(8 - ((myid[dpdkCountRow].length) % 8)), myid[dpdkCountRow].payload, myid[dpdkCountRow].cipher);
                alloc_count++;
                if (alloc_count == NUM_MBUFS)
                {
                    start_free = 1;
                    alloc_count = 0;
                    free_count = 0;
                }
            }
            dpdkCountRow++;
        }
    }
    else
    {
        time_t start, stop;
        printHeader(args);
        start = clock();
        while (1)
        {
            stop = clock();
            if (stop - start >= (5 * CLOCKS_PER_SEC))
            {
                showTime(time);
                start = clock();
            }
            while (dpdkCountRow < args->countRow)
            {
                time->start = clock();
                if (args->type == auth || args->type == both)
                {
                    if (start_free)
                    {
                        dpdkFree(&arg, free_count);
                        free_count++;
                    }
                    dpdkAlloc(&arg, alloc_count);
                    dpdkIntegrity(args->algo, arg.cdev_id, arg.session[0], arg.crypto_ops[alloc_count], arg.mbufs[alloc_count], myid[dpdkCountRow].count, myid[dpdkCountRow].bearer, myid[dpdkCountRow].dir, (myid[dpdkCountRow].length + 7) / 8, myid[dpdkCountRow].payload, myid[dpdkCountRow].mac);
                    alloc_count++;
                    if (alloc_count == NUM_MBUFS)
                    {
                        start_free = 1;
                        alloc_count = 0;
                        free_count = 0;
                    }
                }
                if (args->type == cipher || args->type == both)
                {
                    if (start_free)
                    {
                        dpdkFree(&arg, free_count);
                        free_count++;
                    }
                    dpdkAlloc(&arg, alloc_count);
                    dpdkCiphering(args->algo, arg.cdev_id, arg.session[1], arg.crypto_ops[alloc_count], arg.mbufs[alloc_count], myid[dpdkCountRow].count, myid[dpdkCountRow].bearer, myid[dpdkCountRow].dir, (myid[dpdkCountRow].length + 7) / 8, (u8)(8 - ((myid[dpdkCountRow].length) % 8)), myid[dpdkCountRow].payload, myid[dpdkCountRow].cipher);
                    alloc_count++;
                    if (alloc_count == NUM_MBUFS)
                    {
                        start_free = 1;
                        alloc_count = 0;
                        free_count = 0;
                    }
                }
                time->stop = clock();
                timeCalc(time);
                dpdkCountRow++;
            }
            dpdkCountRow = 0;
        }
    }
    dpdkCryptodevStop(&arg);

    sem_post(args->semaphore);
    pthread_exit(NULL);
}

void *PduCreateThread(void *vargp)
{
    struct thread_arguments *args = vargp;
    struct pdcpPara *para = (struct pdcpPara *)args->para_ptr;
    struct pdcp_pdu *pduAddress = (struct pdcp_pdu *)args->pduAddress_ptr;
    u32 countRow = (args->countRow);
    sem_wait(args->semaphore);

    for (int i = 0; i < args->countRow; i++)
    {
        pduAddress[i].DC_field = 0;
        pduAddress[i].sqnum = para[i].count;
        pduAddress[i].data = para[i].cipher;
        pduAddress[i].length = (para[i].length + 7) / 8;
        pduAddress[i].maci = para[i].mac;
    }
    sem_post(args->semaphore);

    pthread_exit(NULL);
}

void *ComposeThread(void *vargp)
{
    struct thread_arguments *args = (struct thread_arguments *)vargp;
    struct pdcp_pdu *pduAddress = (struct pdcp_pdu *)args->pduAddress_ptr;

    sem_wait(args->semaphore);

    for (int p = 0; p < args->countRow; p++)
    {
        args->output_ptr[p] = (u8 *)malloc(MAX_MSG_PER_TESTCASE * sizeof(u8));
        compose(pduAddress + p, (args->output_ptr)[p], &((pduAddress + p)->length));
    }
    sem_post(args->semaphore);

    pthread_exit(NULL);
}

void *WriteFileThread(void *vargp)
{
    struct thread_arguments *args = (struct thread_arguments *)vargp;
    struct pdcp_pdu *pduAddress = (struct pdcp_pdu *)args->pduAddress_ptr;
    // pthread_mutex_t *lock = (pthread_mutex_t *)args->lock;
    u8 **output = (u8 **)args->output_ptr;

    // pthread_mutex_lock(lock);
    sem_wait(args->semaphore);

    FILE *f = fopen("testcase/outputSW.txt", "a");

    for (int i = 0; i < args->countRow; i++)
    {
        char x[2 * pduAddress[i].length];
        for (int j = 0; j < pduAddress[i].length; j++)
        {
            sprintf(x + 2 * j, "%02X", output[i][j]);
        }
        fprintf(f, "%s\n", x);
        free(output[i]);
    };
    fclose(f);
    sem_post(args->semaphore);

    pthread_exit(NULL);
};