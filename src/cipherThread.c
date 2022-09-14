#include<stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include "pdcp.h"
#include "snow_3g.h"
#include "zuc.h"
#include "aes_ctr.h"

void* cipherThread(void *arg)
{
    struct pdcp_pdu * pduPointer = (struct pdcp_pdu *)arg;
    struct pdcp_pdu pdu = *pduPointer;
    
    // //TEST SNOW3G
    // snow_3g_ciphering(pdu.key, pdu.count, pdu.bearer, pdu.direction, pdu.length, pdu.plaintext);

    // //TEST ZUC
    // zuc_ciphering(pdu.key, pdu.count, pdu.bearer, pdu.direction, pdu.length, pdu.plaintext);
    
    //TEST AES CTR
    aes_ctr_ciphering(pdu.key, pdu.count, pdu.bearer, pdu.direction, pdu.length, pdu.plaintext);

    printf("\nThread processing\n");
    return (void*) cipher;
}