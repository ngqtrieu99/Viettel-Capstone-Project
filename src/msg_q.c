#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/msg.h>
#include <errno.h>
#include "msg_q.h"
#include <time.h>

void write_msg_q(char *arg, int n)
{
    key_t key;
    int msgid;
    // int count=0;
    // printf("%s\n", arg);
    // ftok to generate unique key
    key = ftok("pdcp", n);
    struct mesg_buffer msgbuf;
    // msgget creates a message queue
    // and returns identifier
    // msgid = msgget(key, 0660 | IPC_CREAT);
    while ((msgid = msgget(key, 0660 | IPC_CREAT | IPC_EXCL)) < 0)
    {
        usleep(1);
    }
    msgbuf.mesg_type = 1;
    // printf("%s\n", arg);
    strcpy(msgbuf.mesg_text, arg);
    size_t msgsz = strlen(msgbuf.mesg_text);
    // printf("%ld\n", msgsz);
    // msgsnd(msgid, &msgbuf, msgsz, IPC_NOWAIT);
    while (msgsnd(msgid, &msgbuf, msgsz, IPC_NOWAIT) < 0)
    {
        usleep(1);
    }
    // printf("Send %d %d\n", n, msgid);
}

void read_msg_q(char *arg, int n)
{
    key_t key;
    int msgid;

    // ftok to generate unique key
    key = ftok("pdcp", n);
    struct mesg_buffer *msgbuf = (struct mesg_buffer *)malloc(sizeof(struct mesg_buffer) * MAX_MSG_LEN);
    // struct mesg_buffer msgbuf;
    // msgget creates a message queue
    // and returns identifier

    while ((msgid = msgget(key, 0660)) < 0)
    {
        usleep(1);
    }

    while (msgrcv(msgid, msgbuf, MAX_MSG_LEN, 1, IPC_NOWAIT) < 0)
    {
        usleep(1);
    }
    // printf("%d\n", msgid);
    // printf("%ld\n", strlen(msgbuf->mesg_text));
    strcpy(arg, msgbuf->mesg_text);
    // printf("%ld\n", strlen(arg));
    // free(msgbuf);

    // to destroy the message queue
    msgctl(msgid, IPC_RMID, NULL);
}