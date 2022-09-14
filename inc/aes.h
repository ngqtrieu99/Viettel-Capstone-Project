#ifndef _AES_CTR_H
#define _AES_CTR_H

#include "pdcp.h"

void KeyExpansionCore(u8* in, u8 i);
void KeyExpansion(u8* inputKey, u8* expandedKeys);
void SubBytes(u8* state);
void ShiftRows(u8* state);
void MixColumns(u8* state);
void AddRoundKey(u8* state, u8* roundKey);

void AES_Encrypt(u8* state, u8* key);

void aes_ctr_ciphering(u8* CK, int COUNT, int BEARER, int DIRECTION, int LENGTH, u8* data, u8* output);

void generate_subkey (u8* key, u8*k1, u8* k2);

void aes_cmac_integrity(u8* key, int count, int bearer, int dir, int length, u8* data, u8* mac);

#endif /* _AES_CTR_H */