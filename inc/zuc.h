#ifndef _ZUC_H
#define _ZUC_H

#include "pdcp.h"
/*
 * ZUC keystream generator
 * k: secret key (input, 16 bytes)
 * iv: initialization vector (input, 16 bytes)
 * Keystream: produced keystream (output, variable length)
 * KeystreamLen: length in bits requested for the keystream (input)
*/
void zuc_initialize(u8* k, u8* iv);
void zuc_generate_key_stream(u32* pKeystream, u32 KeystreamLen);

/*
 * CK: ciphering key
 * COUNT: frame counter
 * BEARER: radio bearer
 * DIRECTION
 * LENGTH: length of the frame in bits
 * M: original message (input)
 * C: processed message (output)
*/
void zuc_ciphering(u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u8* data, u8* output);

/*
 * IK: integrity key
 * COUNT: frame counter
 * BEARER: radio bearer
 * DIRECTION
 * LENGTH: length of the frame in bits
 * M: original message (input)
 * C: processed message (output)
*/
void zuc_integrity(u8* IK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u8* M, u8* MAC);


#endif /* _ZUC_H */
