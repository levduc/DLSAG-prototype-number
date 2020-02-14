//
// Created by dduck on 2/3/20.
//

#include "../include/dlsag.h"
#include "../include/helper.h"

void dlsag_gen_garbage_PKs(dlsagPK *vecPK, uint32_t ringSize)
{
    /*Generate n-1 garbage dlsag public keys*/
    for (uint32_t i = 0; i < ringSize-1; i++)
    {
        /*generate n-1 random private keys*/
        unsigned char sk0[crypto_core_ed25519_SCALARBYTES];
        unsigned char sk1[crypto_core_ed25519_SCALARBYTES];
        crypto_core_ed25519_scalar_random(sk0);
        crypto_core_ed25519_scalar_random(sk1);
        /*compute public key from those random secret keys*/
        crypto_scalarmult_ed25519_base_noclamp(vecPK[i].pkb0,sk0);
        crypto_scalarmult_ed25519_base_noclamp(vecPK[i].pkb1,sk1);
    }
}

void dlsag_keygen(dlsag_keyPair *keyPair)
{
    crypto_core_ed25519_scalar_random(keyPair->dlsag_sk0);
    crypto_scalarmult_ed25519_base_noclamp(keyPair->dlsag_pk0, keyPair->dlsag_sk0);
    crypto_core_ed25519_scalar_random(keyPair->dlsag_sk1);
    crypto_scalarmult_ed25519_base_noclamp(keyPair->dlsag_pk1, keyPair->dlsag_sk1);
}

int dlsag_sign(dlsag_signature *signature, dlsag_keyPair *keyPair, uint8_t* message, uint32_t message_len,
               uint32_t ringSize, dlsagPK *vecPK, bool b)
{
    // verifying location of the public key
    if(memcmp(keyPair->dlsag_pk0, vecPK[ringSize-1].pkb0,crypto_core_ed25519_BYTES) != 0)
        return -1;
    if(memcmp(keyPair->dlsag_pk1, vecPK[ringSize-1].pkb1,crypto_core_ed25519_BYTES) != 0)
        return -1;

    // checking bit b;
    unsigned char sk[crypto_core_ed25519_SCALARBYTES];
    unsigned char pk[crypto_core_ed25519_BYTES];
    if(b)
    {
        memcpy(sk,keyPair->dlsag_sk0,crypto_core_ed25519_SCALARBYTES);
        memcpy(pk,keyPair->dlsag_pk1,crypto_core_ed25519_SCALARBYTES);
    }
    else
    {
        memcpy(sk,keyPair->dlsag_sk1,crypto_core_ed25519_SCALARBYTES);
        memcpy(pk,keyPair->dlsag_pk0,crypto_core_ed25519_SCALARBYTES);
    }

    // len(tx||L0||R0)
    uint32_t inputLength = message_len + 2*crypto_core_ed25519_BYTES;
    // Compute key image
    if(crypto_scalarmult_ed25519_noclamp(signature->keyImage, sk, pk))                    // I = sk0*pk1 or sk1*pk0
        return -1;
    // Allocate number of scalar points
    // TODO check
    signature->scalarPoints = (edSK*) malloc((ringSize)*sizeof(edSK));
    //compute h0
    uint8_t hashInput[inputLength];
    memset(hashInput, 0, inputLength);       			                          // (00||0...0||0...0)
    memcpy(hashInput, message, message_len);		                   			      // (tx||0...0||0...0)
    crypto_core_ed25519_scalar_random(signature->scalarPoints[0].skb); 			      // sampling s_0'
    // compute L0
    uint8_t L0[crypto_core_ed25519_BYTES];                                            // L_0
    crypto_scalarmult_ed25519_base_noclamp(L0, signature->scalarPoints[0].skb);       // L_0 = s_0'*G
    // compute R0
    uint8_t R0[crypto_core_ed25519_BYTES];                                            // R_0
    if(crypto_scalarmult_ed25519_noclamp(R0, signature->scalarPoints[0].skb, pk))     // R_0 = s_0'pk
    {
        return -1;
    }
    memcpy(&hashInput[message_len], L0, crypto_core_ed25519_BYTES); 			                     // (tx||L0||0...0)
    memcpy(&hashInput[message_len+crypto_core_ed25519_BYTES], R0, crypto_core_ed25519_BYTES); // (tx||L0||R0)
    // h0
    uint8_t out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(out, hashInput, inputLength);                                  // h0 = H(tx||L0||R0)
    memcpy(signature->h0, out, crypto_hash_sha256_BYTES);

    uint8_t hi[crypto_core_ed25519_SCALARBYTES];                                      // h_i
    memcpy(hi,signature->h0,crypto_core_ed25519_SCALARBYTES);
    uint8_t Li[crypto_core_ed25519_BYTES];                                            // L_i
    uint8_t Ri[crypto_core_ed25519_BYTES];
    for (uint32_t i = 1; i < ringSize; i++)
    {
        // sample s1, ..., s_(RingSize-1)
        crypto_core_ed25519_scalar_random(signature->scalarPoints[i].skb);
        // Compute Li
        uint8_t left_Li[crypto_core_ed25519_BYTES];
        crypto_scalarmult_ed25519_base_noclamp(left_Li, signature->scalarPoints[i].skb);     // si*G
        uint8_t right_Li[crypto_core_ed25519_BYTES];
        if(b)
        {
            if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[i-1].pkb0))              // h_{i-1}*pk_{i-1}
            {
                return -1;
            }
        }
        else{
            if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[i-1].pkb1))              // h_{i-1}*pk_{i-1}
            {
                return -1;
            }
        }
        crypto_core_ed25519_add(Li, left_Li,right_Li);                                // si*G + hi*vecPK[i-1]

        // Compute Ri
        uint8_t left_Ri[crypto_core_ed25519_BYTES];
        uint8_t right_Ri[crypto_core_ed25519_BYTES];

        if(b){
            if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[i].skb, vecPK[i-1].pkb1))  // si*h(VecPK[i-1])
            {
                return -1;
            }
        }
        else{
            if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[i].skb, vecPK[i-1].pkb0))  // si*h(VecPK[i-1])
            {
                return -1;
            }
        }

        if(crypto_scalarmult_ed25519_noclamp(right_Ri, hi, signature->keyImage))          //h_{i-1}*I
            return -1;
        crypto_core_ed25519_add(Ri,left_Ri,right_Ri);
        // computing h_i = H(tx||Li||Ri)
        memcpy(&hashInput[message_len], Li, crypto_core_ed25519_BYTES); 			                     //(tx||Li||0...0)
        memcpy(&hashInput[message_len+crypto_core_ed25519_BYTES], Ri, crypto_core_ed25519_BYTES); //(tx||Li||Ri)
        crypto_hash_sha256(hi, hashInput, inputLength);
        crypto_core_ed25519_scalar_reduce(hi,hi);
    }

    /** the following computation does not produce an s0 that closes the ring*/
    /*there is something wrong with the scalar arithmetic*/
    // we have  h_{n-1} and s_0'
    /* Compute real s0 = s0' - h_{n-1}sk*/
    uint8_t tempProduct[crypto_core_ed25519_SCALARBYTES];
    // tempProduct = h_{n-1}*sk
    crypto_core_ed25519_scalar_mul(tempProduct, hi, sk);
    uint8_t tempS0[crypto_core_ed25519_SCALARBYTES];
    crypto_core_ed25519_scalar_sub(tempS0, signature->scalarPoints[0].skb, tempProduct);
    // crypto_core_ed25519_scalar_sub(tempS0, tempProduct, signature->scalarPoints[0].skb);
    // tempS0 = s0' - tempProduct
    memcpy(signature->scalarPoints[0].skb, tempS0, crypto_core_ed25519_SCALARBYTES);
    signature->b = b;
    // =================================================================================
    return 1;
}

int dlsag_verify(dlsag_signature *signature, uint8_t* message, uint32_t message_len, uint32_t ringSize, dlsagPK *vecPK)
{
    bool b = signature->b;
    // len(tx||L0||R0)
    uint32_t inputLength = message_len + 2*crypto_core_ed25519_BYTES;
    // Allocate number of scalar points
    // TODO check
    //compute h0
    uint8_t hashInput[inputLength];
    memset(hashInput, 0, inputLength);       			                          // (00||0...0||0...0)
    memcpy(hashInput, message, message_len);		                   			      // (tx||0...0||0...0)
    uint8_t hi[crypto_core_ed25519_SCALARBYTES];                                      // h_i
    memcpy(hi,signature->h0,crypto_core_ed25519_SCALARBYTES);

    // Compute Li
    uint8_t Li[crypto_core_ed25519_BYTES];                                            // L_i
    uint8_t left_Li[crypto_core_ed25519_BYTES];
    uint8_t right_Li[crypto_core_ed25519_BYTES];

    // Compute Ri
    uint8_t Ri[crypto_core_ed25519_BYTES];
    uint8_t left_Ri[crypto_core_ed25519_BYTES];
    uint8_t right_Ri[crypto_core_ed25519_BYTES];
    for (uint32_t i = 1; i < ringSize; i++)
    {
        crypto_scalarmult_ed25519_base_noclamp(left_Li, signature->scalarPoints[i].skb);     // si*G
        if(b)
        {
            if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[i-1].pkb0))              // h_{i-1}*pk_{i-1}
            {
                return -1;
            }
        }
        else{
            if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[i-1].pkb1))              // h_{i-1}*pk_{i-1}
            {
                return -1;
            }
        }
        crypto_core_ed25519_add(Li, left_Li,right_Li);                                // si*G + hi*vecPK[i-1]


        if(b){
            if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[i].skb, vecPK[i-1].pkb1))  // si*h(VecPK[i-1])
            {
                return -1;
            }
        }
        else{
            if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[i].skb, vecPK[i-1].pkb0))  // si*h(VecPK[i-1])
            {
                return -1;
            }
        }

        if(crypto_scalarmult_ed25519_noclamp(right_Ri, hi, signature->keyImage))          //h_{i-1}*I
            return -1;
        crypto_core_ed25519_add(Ri,left_Ri,right_Ri);
        // computing h_i = H(tx||Li||Ri)
        memcpy(&hashInput[message_len], Li, crypto_core_ed25519_BYTES); 			                     //(tx||Li||0...0)
        memcpy(&hashInput[message_len+crypto_core_ed25519_BYTES], Ri, crypto_core_ed25519_BYTES); //(tx||Li||Ri)
        crypto_hash_sha256(hi, hashInput, inputLength);
        crypto_core_ed25519_scalar_reduce(hi,hi);
    }
    // Compute Li
    crypto_scalarmult_ed25519_base_noclamp(left_Li, signature->scalarPoints[0].skb);     // si*G
    if(b)
    {
        if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[ringSize-1].pkb0))              // h_{i-1}*pk_{i-1}
        {
            return -1;
        }
    }
    else{
        if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[ringSize-1].pkb1))              // h_{i-1}*pk_{i-1}
        {
            return -1;
        }
    }
    crypto_core_ed25519_add(Li, left_Li,right_Li);                                // si*G + hi*vecPK[i-1]

    // Compute Ri
    if(b){
        if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[0].skb, vecPK[ringSize-1].pkb1))  // si*h(VecPK[i-1])
        {
            return -1;
        }
    }
    else{
        if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[0].skb, vecPK[ringSize-1].pkb0))  // si*h(VecPK[i-1])
        {
            return -1;
        }
    }
    if(crypto_scalarmult_ed25519_noclamp(right_Ri, hi, signature->keyImage))          //h_{i-1}*I
        return -1;
    crypto_core_ed25519_add(Ri,left_Ri,right_Ri);
    // computing h_i = H(tx||Li||Ri)
    memcpy(&hashInput[message_len], Li, crypto_core_ed25519_BYTES); 			                     //(tx||Li||0...0)
    memcpy(&hashInput[message_len+crypto_core_ed25519_BYTES], Ri, crypto_core_ed25519_BYTES); //(tx||Li||Ri)
    crypto_hash_sha256(hi, hashInput, inputLength);
    return sodium_memcmp(hi,signature->h0, crypto_core_ed25519_SCALARBYTES);
}
