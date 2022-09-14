#ifndef _CRYPTO_DPDK_
#define _CRYPTO_DPDK_

#include <rte_cryptodev.h>
#include <stdint.h>

#include "testbench.h"

#define MAX_SESSIONS 100
#define NUM_MBUFS 65536
#define POOL_CACHE_SIZE 128
// #define BURST_SIZE 1
#define IV_LENGTH 16
#define KEY_LENGTH 16
#define DIGEST_LENGTH 4
#define IV_OFFSET (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))

void dpdkCiphering(uint8_t algo, uint8_t cdev_id, struct rte_cryptodev_sym_session *session, struct rte_crypto_op *crypto_ops, struct rte_mbuf *mbufs, uint32_t count, uint32_t bearer, uint32_t dir, uint32_t length, uint8_t redundant, uint8_t *plaintext, uint8_t *ciphertext);
void dpdkIntegrity(uint8_t algo, uint8_t cdev_id, struct rte_cryptodev_sym_session *session, struct rte_crypto_op *crypto_ops, struct rte_mbuf *mbufs, uint32_t count, uint32_t bearer, uint32_t dir, uint32_t length, uint8_t *plaintext, uint8_t *digest);

#endif