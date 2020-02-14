//
// Created by dduck on 2/3/20.
#include <cstdint>
#include <stdio.h>
#include <sodium.h>
#include <iostream>
#include <string.h>
#include "lsag.h"
//
#ifndef DLSAG_DLSAG_H
#define DLSAG_DLSAG_H

struct dlsag_keyPair{
    uint8_t dlsag_sk0[crypto_core_ed25519_SCALARBYTES];
    uint8_t dlsag_sk1[crypto_core_ed25519_SCALARBYTES];
    uint8_t dlsag_pk0[crypto_core_ed25519_BYTES];
    uint8_t dlsag_pk1[crypto_core_ed25519_BYTES];
};

struct dlsag_signature{
    struct edSK *scalarPoints;
    uint8_t h0[crypto_core_ed25519_SCALARBYTES];
    uint8_t keyImage[crypto_core_ed25519_BYTES];
    bool b;
};

struct dlsagSK{
    uint8_t skb0[crypto_core_ed25519_SCALARBYTES];
    uint8_t skb1[crypto_core_ed25519_SCALARBYTES];
};

struct dlsagPK{
    uint8_t pkb0[crypto_core_ed25519_BYTES];
    uint8_t pkb1[crypto_core_ed25519_BYTES];
};

//void dlsag_gen_garbage_PKs(edPK *vecPK, uint32_t ringSize);

void dlsag_gen_garbage_PKs(dlsagPK *vecPK, uint32_t ringSize);

void dlsag_keygen(dlsag_keyPair *keyPair);

int dlsag_sign(dlsag_signature *signature, dlsag_keyPair *keyPair, uint8_t* message, uint32_t message_len,
              uint32_t ringSize, dlsagPK *vecPK,bool b);
int dlsag_verify(dlsag_signature *signature, uint8_t* message, uint32_t message_len, uint32_t ringSize, dlsagPK *vecPK);

#endif //DLSAG_DLSAG_H
