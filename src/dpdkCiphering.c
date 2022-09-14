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

uint8_t power(uint8_t a, uint8_t b) {
	if (!b && a != 0)
		return 1;
	else if (b > 0)
		return a * power(a, b-1);
	else
		return 0;
}

int verify_cipher_op(struct rte_crypto_op *op, uint32_t data_len, uint8_t redundant, uint8_t *outptext)
{
    const struct rte_mbuf *m;
    uint8_t *data;
    uint32_t len = 0;
    uint32_t cipher_offset;
    int res = 0;

    if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
        return 1;

    if (op->sym->m_dst)
        m = op->sym->m_dst;
    else
        m = op->sym->m_src;

    len = 0;
    while (m != 0) {
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
    while (m != 0) {
        memcpy(data + len, rte_pktmbuf_mtod(m, uint8_t *), m->data_len);
        len += m->data_len;
        m = m->next;
    }

    cipher_offset = 0;
    if ((redundant > 0) && (redundant < 8)) {
    redundant = power(2, redundant) - 1;
    (data + cipher_offset)[data_len - 1] &= ~redundant;
    }
    for (uint32_t i = 0; i < data_len; ++i) {
        outptext[i] = (data + cipher_offset)[i];
    }

    rte_free(data);
    return !!res;
}

void dpdkCiphering(uint8_t algo, uint8_t cdev_id, struct rte_cryptodev_sym_session *session, struct rte_crypto_op *crypto_ops, struct rte_mbuf *mbufs, uint32_t count, uint32_t bearer, uint32_t dir, uint32_t length, uint8_t redundant, uint8_t *plaintext, uint8_t *ciphertext)
{
    uint64_t num_enqueued_ops = 0, total_num_enqueued_ops = 0, num_enqueued_ops_failed = 0;
    uint64_t num_dequeued_ops = 0, total_num_dequeued_ops = 0, num_dequeued_ops_failed = 0;
    uint64_t num_ops_failed = 0;
    uint8_t *mbuf_data;

    uint8_t iv_pointer[16];

    switch (algo) {
        case snow3g:
            iv_pointer[0] = count >> 24;
            iv_pointer[1] = count >> 16;
            iv_pointer[2] = count >> 8;
            iv_pointer[3] = count;
            iv_pointer[4] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 24;
            iv_pointer[5] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 16;
            iv_pointer[6] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 8;
            iv_pointer[7] = ((bearer << 27) | ((dir & 0x1) << 26));
            iv_pointer[8] = count >> 24;
            iv_pointer[9] = count >> 16;
            iv_pointer[10] = count >> 8;
            iv_pointer[11] = count;
            iv_pointer[12] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 24;
            iv_pointer[13] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 16;
            iv_pointer[14] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 8;
            iv_pointer[15] = ((bearer << 27) | ((dir & 0x1) << 26));
            break;
        case aes:
            iv_pointer[0] = count >> 24;
            iv_pointer[1] = count >> 16;
            iv_pointer[2] = count >> 8;
            iv_pointer[3] = count;
            iv_pointer[4] = ((bearer << 3) | ((dir&1)<<2)) & 0xFC;
            iv_pointer[5] = 0;
            iv_pointer[6] = 0;
            iv_pointer[7] = 0;
            iv_pointer[8] = 0;
            iv_pointer[9] = 0;
            iv_pointer[10] = 0;
            iv_pointer[11] = 0;
            iv_pointer[12] = 0;
            iv_pointer[13] = 0;
            iv_pointer[14] = 0;
            iv_pointer[15] = 0;
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
            iv_pointer[8] = count >> 24;
            iv_pointer[9] = count >> 16;
            iv_pointer[10] = count >> 8;
            iv_pointer[11] = count;
            iv_pointer[12] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 24;
            iv_pointer[13] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 16;
            iv_pointer[14] = ((bearer << 27) | ((dir & 0x1) << 26)) >> 8;
            iv_pointer[15] = ((bearer << 27) | ((dir & 0x1) << 26));
            break;
        default:
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
        memcpy(mbuf_data, plaintext, length);

        op->sym->cipher.data.offset = 0;
        op->sym->cipher.data.length = length;
        // if ((cipher_xform.cipher.algo == RTE_CRYPTO_CIPHER_SNOW3G_UEA2) ||(cipher_xform.cipher.algo == RTE_CRYPTO_CIPHER_ZUC_EEA3))
        if ((algo == snow3g) || (algo == zuc))
            op->sym->cipher.data.length <<= 3;

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
        num_dequeued_ops = rte_cryptodev_dequeue_burst(cdev_id, 0,
                                                       &dequeued_ops, 1);

        if (num_dequeued_ops == 0)
        {
            num_dequeued_ops_failed++;
            continue;
        }

        // for (int i = 0; i < num_dequeued_ops; i++)
        // {
            if (verify_cipher_op(dequeued_ops, length, redundant, ciphertext))
                num_ops_failed++;
        // }

        total_num_dequeued_ops += num_dequeued_ops;

        // rte_mempool_put_bulk(crypto_op_pool, (void **)dequeued_ops,
        //                      num_dequeued_ops);
    } while (total_num_dequeued_ops < num_enqueued_ops);
}
