#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "testbench.h"
#include "msg_q.h"

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

void *DataSendThread(void *vargp)
{
    double *dataCycle = (double *)vargp;
    char buf[MAX_MSG_LEN + 2];
    char arg[3000];
    FILE *fp = fopen(INPUT_FILE, "r");
    if (fp == NULL)
    {
        return NULL;
    }
    uint8_t i = 1;

    // Go to start of file txt
    fseek(fp, 0, SEEK_SET);
    while (fgets(buf, MAX_MSG_LEN + 2, fp) != NULL)
    {
        if (i == 0)
            i = 1;
        buf[strlen(buf) - 1] = '\0'; // eat the newline fgets() stores
        strcpy(arg, buf);
        // printf("%ld\n", strlen(arg));
        write_msg_q(arg, i);
        i++;
    }

    write_msg_q("", i);
    fclose(fp);

    pthread_exit(NULL);
}

void *AccuracyCalcThread(void *vargp)
{
    uint8_t *algo = (uint8_t *)vargp;
    char buf1[MAX_MSG_LEN + 2], buf2[MAX_MSG_LEN + 2];
    int retval;
    char *str;

    printf("Check file...\n");

    switch (*algo)
    {
    case snow3g:
        str = "testcase/correct_output_snow3g.txt";
        break;
    case aes:
        str = "testcase/correct_output_aes.txt";
        break;
    case zuc:
        str = "testcase/correct_output_zuc.txt";
        break;
    default:
        break;
    }

    FILE *fp1 = fopen("testcase/output.txt", "r");
    if (fp1 == NULL)
    {
        printf("Failed to open file1\n");
        return NULL;
    }
    FILE *fp2 = fopen(str, "r");
    if (fp2 == NULL)
    {
        printf("Failed to open file2\n");
        return NULL;
    }

    fseek(fp1, 0, SEEK_SET);
    fseek(fp2, 0, SEEK_SET);
    while (fgets(buf1, sizeof(buf1), fp1) != NULL)
    {
        buf1[strlen(buf1) - 1] = '\0'; // eat the newline fgets() stores
        if (fgets(buf2, sizeof(buf2), fp2) != NULL)
            buf2[strlen(buf2) - 1] = '\0';
        if (strcmp(buf1, buf2))
        {
            printf("Failed\n");
            pthread_exit(NULL);
        }
    }
    printf("Correct\n");
    pthread_exit(NULL);
}