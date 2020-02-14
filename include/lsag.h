//
// Created by dduck on 2/3/20.
//

#include <cstdint>
#include <stdio.h>
#include <sodium.h>
#include <iostream>
#include <string.h>


#ifndef DLSAG_LSAG_H
#define DLSAG_LSAG_H
struct lsag_keyPair{
    uint8_t lsag_sk[crypto_core_ed25519_SCALARBYTES];
    uint8_t lsag_pk[crypto_core_ed25519_BYTES];
};

struct lsag_signature{
    struct edSK *scalarPoints;
    uint8_t h0[crypto_core_ed25519_SCALARBYTES];
    uint8_t keyImage[crypto_core_ed25519_BYTES];
};

struct edSK{
    uint8_t skb[crypto_core_ed25519_SCALARBYTES];
};

struct edPK{
    uint8_t pkb[crypto_core_ed25519_BYTES];
};

void lsag_gen_garbage_PKs(edPK *vecPK, uint32_t ringSize);
void lsag_keygen(lsag_keyPair *keyPair);
int lsag_sign(lsag_signature *signature, lsag_keyPair *keyPair, uint8_t* message, uint32_t message_len,
              uint32_t ringSize, edPK *vecPK);
int lsag_verify(lsag_signature *signature, uint8_t* message, uint32_t message_len, uint32_t ringSize, edPK *vecPK);
#endif //DLSAG_LSAG_H
