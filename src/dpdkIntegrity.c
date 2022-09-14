#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <rte_cryptodev.h>
#include <rte_malloc.h>

#include "crypto-dpdk.h"

int verify_auth_op(struct rte_crypto_op *op, uint32_t data_len, uint8_t *digest)
{
    const struct rte_mbuf *m;
    uint8_t *data;
    uint32_t len = 0;
    uint32_t auth_offset;
    int res = 0;

    if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
        return 1;

    if (op->sym->m_dst)
        m = op->sym->m_dst;
    else
        m = op->sym->m_src;

    len = 0;
    while (m != 0)
    {
        len = m->data_len;
        m = m->next;
    }

    data = rte_malloc(NULL, len, 0);
    if (data == NULL)
        return 1;

    if (op->sym->m_dst)
        m = op->sym->m_dst;
    else
        m = op->sym->m_src;

    len = 0;
    while (m != 0)
    {
        memcpy(data + len, rte_pktmbuf_mtod(m, uint8_t *), m->data_len);
        len += m->data_len;
        m = m->next;
    }

    auth_offset = 0;

    for (uint32_t i = 0; i < DIGEST_LENGTH; ++i)
    {
        digest[i] = (data + auth_offset)[i];
    }

    rte_free(data);
    return !!res;
}

void dpdkIntegrity(uint8_t algo, uint8_t cdev_id, struct rte_cryptodev_sym_session *session, struct rte_crypto_op *crypto_ops, struct rte_mbuf *mbufs, uint32_t count, uint32_t bearer, uint32_t dir, uint32_t length, uint8_t *plaintext, uint8_t *digest)
{
    uint64_t num_enqueued_ops = 0, total_num_enqueued_ops = 0, num_enqueued_ops_failed = 0;
    uint64_t num_dequeued_ops = 0, total_num_dequeued_ops = 0, num_dequeued_ops_failed = 0;
    uint64_t num_ops_failed = 0;
    uint8_t *mbuf_data;

    uint32_t fresh = bearer << 27;

    uint8_t iv_pointer[16];
    uint8_t M[length+8];

    switch (algo)
    {
    case snow3g:
        iv_pointer[0] = count >> 24;
        iv_pointer[1] = count >> 16;
        iv_pointer[2] = count >> 8;
        iv_pointer[3] = count;
        iv_pointer[4] = fresh >> 24;
        iv_pointer[5] = fresh >> 16;
        iv_pointer[6] = fresh >> 8;
        iv_pointer[7] = fresh;
        iv_pointer[8] = (count ^ (dir << 31)) >> 24;
        iv_pointer[9] = (count ^ (dir << 31)) >> 16;
        iv_pointer[10] = (count ^ (dir << 31)) >> 8;
        iv_pointer[11] = (count ^ (dir << 31));
        iv_pointer[12] = (fresh ^ (dir << 15)) >> 24;
        iv_pointer[13] = (fresh ^ (dir << 15)) >> 16;
        iv_pointer[14] = (fresh ^ (dir << 15)) >> 8;
        iv_pointer[15] = (fresh ^ (dir << 15));
        break;
    case aes:
        for (int i = 0; i < length; i++)
            M[length - i - 1 + 8] = plaintext[length - i - 1];
        M[0] = count >> 24;
	    M[1] = count >> 16;
	    M[2] = count >> 8;
	    M[3] =  count;
	    M[4] = ((bearer << 3) | ((dir & 0x1) << 2)) & 0xFC;
	    M[5] = 0;
	    M[6] = 0;
	    M[7] = 0;
        length += 8;
        break;
    case zuc:
        iv_pointer[0] = count >> 24;
        iv_pointer[1] = count >> 16;
        iv_pointer[2] = count >> 8;
        iv_pointer[3] = count;
        iv_pointer[4] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 24;
        iv_pointer[5] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 16;
        iv_pointer[6] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 8;
        iv_pointer[7] = ((bearer << 27) | ((dir & 0x1) << 26));
        iv_pointer[8] = (count >> 24) ^ ((dir & 0x1) << 7);
        iv_pointer[9] = count >> 16;
        iv_pointer[10] = count >> 8;
        iv_pointer[11] = count;
        iv_pointer[12] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 24;
        iv_pointer[13] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 16;
        iv_pointer[14] = (((bearer << 27) | ((dir & 0x1) << 26)) >> 8) ^ ((dir & 0x1) << 7);
        iv_pointer[15] = ((bearer << 27) | ((dir & 0x1) << 26));
        break;
    default:
        rte_exit(EXIT_FAILURE, "Algorithm not supported");
        break;
    }

    /* Initialize the mbufs and append them to the crypto operations. */
    // unsigned int i;
    // for (i = 0; i < BURST_SIZE; i++)
    // {
        mbufs->buf_len = length;
        mbufs->data_off = 0;
        mbufs->data_len = length;
        crypto_ops->sym->m_src = mbufs;
    // }

    /* Set up the crypto operations. */
    // for (i = 0; i < BURST_SIZE; i++)
    // {
        struct rte_crypto_op *op = crypto_ops;
        /* Modify bytes of the IV at the end of the crypto operation */
        uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);

        memcpy(iv_ptr, iv_pointer, IV_LENGTH);

        mbuf_data = rte_pktmbuf_mtod(crypto_ops->sym->m_src, uint8_t *);
        if (algo == aes)
            memcpy(mbuf_data, M, length);
        else
            memcpy(mbuf_data, plaintext, length);

        op->sym->auth.digest.data = rte_pktmbuf_mtod_offset(mbufs, uint8_t *, 0);
        op->sym->auth.digest.phys_addr = rte_pktmbuf_iova_offset(mbufs, 0);
        op->sym->auth.data.offset = 0;
        op->sym->auth.data.length = length;
        if ((algo == snow3g) || (algo == zuc))
        {
            op->sym->auth.data.length <<= 3;
        }

        /* Attach the crypto session to the operation */
        rte_crypto_op_attach_sym_session(op, session);
    // }

    /* Enqueue the crypto operations in the crypto device. */
    num_enqueued_ops = rte_cryptodev_enqueue_burst(cdev_id, 0, &crypto_ops, 1);

    if (num_enqueued_ops < 1)
        num_enqueued_ops_failed++;

    /*
    * Dequeue the crypto operations until all the operations
    * are processed in the crypto device.
    */
    do
    {
        struct rte_crypto_op *dequeued_ops;
        num_dequeued_ops = rte_cryptodev_dequeue_burst(cdev_id, 0, &dequeued_ops, 1);

        if (num_dequeued_ops == 0)
        {
            num_dequeued_ops_failed++;
            continue;
        }

        // for (int i = 0; i < num_dequeued_ops; i++)
        // {
            if (verify_auth_op(dequeued_ops, length, digest))
                num_ops_failed++;
        // }

        total_num_dequeued_ops += num_dequeued_ops;

        // rte_mempool_put_bulk(crypto_op_pool, (void **)dequeued_ops,
        //                      num_dequeued_ops);
    } while (total_num_dequeued_ops < num_enqueued_ops);
}
