#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "testbench.h"
#include "msg_q.h"

int main(void)
{
    int status;
    time_t start, stop;
    double processTime;
    pthread_t thread_id[3];
    double thrp;
    uint8_t param, met, algo, type;

    FILE *fp = fopen(INPUT_FILE, "r");
    if (fp == NULL)
    {
        printf("No input directory\n");
        exit(EXIT_FAILURE);
    }

    // printf("Input throughput in MBps\n");
    // scanf("%lf", &thrp);
    // double dataCycle = (thrp) * 1000000.0 / (1500.0);

    printf("Choose the test param:\n1.Accuracy\n2.Speed\n");
    scanf("%hhd", &param);
    while ((param < 1) || (param > 2))
    {
        printf("\nWrong input!\nPlease input 1 or 2\n");
        scanf("%hhd", &param);
    }

    printf("\nSW or DPDK?\n1.SW\n2.DPDK\n");
    scanf("%hhd", &met);
    while ((met < 1) || (met > 2))
    {
        printf("\nWrong input!\nPlease input 1 or 2\n");
        scanf("%hhd", &met);
    }

    printf("\nChoose the algorithm:\n1.SNOW3G\n2.AES\n3.ZUC\n");
    scanf("%hhd", &algo);
    while ((algo < 1) || (algo > 3))
    {
        printf("\nWrong input!\nPlease input 1, 2 or 3\n");
        scanf("%hhd", &algo);
    }

    if (param == accuracy)
        type = both;
    else
    {
        printf("\nChoose the type:\n1.Integrity\n2.Ciphering\n3.Both\n");
        scanf("%hhd", &type);
        while ((type < 1) || (type > 3))
        {
            printf("\nWrong input!\nPlease input 1, 2 or 3\n");
            scanf("%hhd", &type);
        }
    }

    char str_param[4], str_met[4], str_algo[4], str_type[4];

    sprintf(str_param, "%hhd", param);
    sprintf(str_met, "%hhd", met);
    sprintf(str_algo, "%hhd", algo);
    sprintf(str_type, "%hhd", type);

    pid_t pid = fork();
    if (pid == 0) // child process because return value zero
    {

        printf("\n**********************************\n");
        printf("Hello from Child!\n");
        printf("Waiting for pdcp starting up\n");
        char *args[] = {"./pdcp", "-l 7", str_param, str_met, str_algo, str_type, NULL};
        if (execvp(args[0], args) < 0)
        {
            printf("Error in running pdcp\n");
            return -1;
        }
        printf("Running from child process\n");
        _exit(1);
    }

    else // parent process because return value non-zero.
    {

        // Tao thread gui packet cho PDCP
        setAffinity(thread_id[0], 5);
        pthread_create(&thread_id[0], NULL, DataSendThread, NULL);
        pthread_join(thread_id[0], NULL);
        while (wait(&status) > 0);
        if (param == accuracy)
        {
            pthread_create(&thread_id[1], NULL, AccuracyCalcThread, &algo);
            pthread_join(thread_id[1], NULL);
        }
    }
    printf("\nEnd testbench\n");
}