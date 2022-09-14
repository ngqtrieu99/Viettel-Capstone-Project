#ifndef _MSG_Q_H
#define _MSG_Q_H

#define MAX_MSG_LEN 5000
#define MAX_MSG_PER_TESTCASE 700000

// structure for message queue
struct mesg_buffer {
    long mesg_type;
    char mesg_text[MAX_MSG_LEN];
};

void write_msg_q(char *arg, int n);
void read_msg_q(char *arg, int n);

#endif /* MSG_Q_H */