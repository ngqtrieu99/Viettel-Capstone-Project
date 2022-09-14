#ifndef _PDCP_
#define _PDCP_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "msg_q.h"
#include "crypto-dpdk.h"

#define MAX_COUNTROW 10000

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

u32 tempCountRow;

struct pdcpPara
{
	int dir;
	int bearer;
	int count;
	u32 length;
	char payload[1500];
	// u8 key[16];
	u8 mac[4];
	u8 cipher[1500];
};

typedef struct pdcp_pdu //structure pdcp for 3 format of pdu (SRBs, DRBs with sequence number's length 12 bits and 18 bits)
{
	int DC_field;
	int sqnum;

	u32 length;
	u8 *data;

	u8 *maci; //This is added by gNB PDCP Layer. UE is comparing this with the one it calculated internally
} __attribute__((packed, aligned(1))) pdu;

struct dpdkArg
{
	u8 cdev_id;
	u8 socket_id;
	struct rte_mempool *mbuf_pool;
	struct rte_mempool *crypto_op_pool;
	struct rte_mempool *session_pool;
	struct rte_mempool *session_priv_pool;
	struct rte_cryptodev_sym_session *session[2];
	struct rte_crypto_op *crypto_ops[NUM_MBUFS];
	struct rte_mbuf *mbufs[NUM_MBUFS];
};

struct timeArg
{
	time_t start;
	time_t stop;
	int length;
	u64 totalLength;
	double processTimePerLoop;
	double processTime;
};

struct thread_arguments
{
	struct pdcpPara *para_ptr;
	struct pdcp_pdu *pduAddress_ptr;
	u8 **output_ptr;
	u8 *key;
	u32 count;
	u64 countRow;
	u8 **payload;
	int totalLength;
	u8 param;
	u8 met;
	u8 algo;
	u8 type;
	int argc;
	char **argv;
	struct dpdkArg dpdkArg;
	struct timeArg timArg;
	sem_t *semaphore;
};

//Parsing the string to struct type
void parse_msg(u8 *byte, size_t data_length, size_t maci_length);

void compose(struct pdcp_pdu *compose, u8 *byte, u32 *length);

void *PdcpThread_SW(void *vargp);

void *PdcpThread_DPDK(void *vargp);

void *PdcpReceiveThread(void *vargp);

void *PduCreateThread(void *vargp);

void *ComposeThread(void *vargp);

void *WriteFileThread(void *vargp);

#endif