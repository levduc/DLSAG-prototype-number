//
// Created by dduck on 2/10/20.
//
#include "../include/lsag.h"
#include "../include/helper.h"

/*generate garbage*/
void lsag_gen_garbage_PKs(edPK *vecPK, uint32_t ringSize)
{
    /*Generate n-1 garbage public keys*/
    for (uint32_t i = 0; i < ringSize-1; i++)
    {
        /*generate n-1 random private keys*/
        unsigned char sk[crypto_core_ed25519_SCALARBYTES];
        crypto_core_ed25519_scalar_random(sk);
        /*compute public key from those random secret keys*/
        crypto_scalarmult_ed25519_base_noclamp(vecPK[i].pkb,sk);
    }
}

/*LSAG key generation*/
void lsag_keygen(lsag_keyPair *keyPair)
{
    crypto_core_ed25519_scalar_random(keyPair->lsag_sk);
    crypto_scalarmult_ed25519_base_noclamp(keyPair->lsag_pk, keyPair->lsag_sk);
}

/*LSAG signing*/
int lsag_sign(lsag_signature *signature, lsag_keyPair *keyPair, uint8_t* message, uint32_t message_len,
              uint32_t ringSize, edPK *vecPK)
{
    if(memcmp(keyPair->lsag_pk, vecPK[ringSize-1].pkb,crypto_core_ed25519_BYTES) != 0)
        return -1;
    // len(tx||L0||R0)
    uint32_t inputLength = message_len + 2*crypto_core_ed25519_BYTES;
    uint8_t hashDigest[crypto_core_ed25519_BYTES];                                    // H(pk) ed point
    crypto_core_ed25519_from_uniform(hashDigest, keyPair->lsag_pk);                   // hashDigest = h(pk)
    // Compute key image
    if(crypto_scalarmult_ed25519_noclamp(signature->keyImage, keyPair->lsag_sk, hashDigest))  // I = sk*H(pk)
        return -1;
    // Allocate number of scalar points
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
    if(crypto_scalarmult_ed25519_noclamp(R0, signature->scalarPoints[0].skb, hashDigest))     // R_0 = s_0'*H(pk)
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
        if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[i-1].pkb))              // h_{i-1}*pk_{i-1}
        {
            return -1;
        }
        crypto_core_ed25519_add(Li, left_Li,right_Li);                                // si*G + hi*vecPK[i-1]

        // Compute Ri
        uint8_t left_Ri[crypto_core_ed25519_BYTES];
        uint8_t right_Ri[crypto_core_ed25519_BYTES];
        uint8_t tempHashDigest[32];
        crypto_core_ed25519_from_uniform(tempHashDigest, vecPK[i-1].pkb);                   // h(VecPK[i-1])
        if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[i].skb, tempHashDigest))  // si*h(VecPK[i-1])
        {
            return -1;
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
    crypto_core_ed25519_scalar_mul(tempProduct, hi, keyPair->lsag_sk);
    uint8_t tempS0[crypto_core_ed25519_SCALARBYTES];
    crypto_core_ed25519_scalar_sub(tempS0, signature->scalarPoints[0].skb, tempProduct);
    // crypto_core_ed25519_scalar_sub(tempS0, tempProduct, signature->scalarPoints[0].skb);
    // tempS0 = s0' - tempProduct
    memcpy(signature->scalarPoints[0].skb, tempS0, crypto_core_ed25519_SCALARBYTES);
    return 1;
}
int lsag_verify(lsag_signature *signature, uint8_t* message, uint32_t message_len, uint32_t ringSize, edPK *vecPK)
{
    // Message||L0||R0
    uint32_t inputLength = message_len + 2*crypto_core_ed25519_BYTES;
    uint8_t hi[crypto_core_ed25519_SCALARBYTES];                                      // h_i
    uint8_t Li[crypto_core_ed25519_BYTES];                                            // L_i
    uint8_t Ri[crypto_core_ed25519_BYTES];                                            // R_i
    uint8_t left_Li[crypto_core_ed25519_BYTES];
    uint8_t right_Li[crypto_core_ed25519_BYTES];
    uint8_t left_Ri[crypto_core_ed25519_BYTES];
    uint8_t right_Ri[crypto_core_ed25519_BYTES];

    uint8_t hashInput[inputLength];
    memset(hashInput, 0, inputLength);     			                              // (00||0...0||0...0)
    memcpy(hashInput, message, message_len);                                          // (tx||0...0||0...0)
    memcpy(hi,signature->h0,crypto_core_ed25519_SCALARBYTES);

    for (uint32_t i = 1; i < ringSize; i++)
    {
        // Compute Li
        crypto_scalarmult_ed25519_base_noclamp(left_Li, signature->scalarPoints[i].skb);
        if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[i-1].pkb))
        {
            printf("[-] failed to compute Li");
            return -1;
        }
        crypto_core_ed25519_add(Li, left_Li,right_Li);
        // Compute Ri
        uint8_t tempHashDigest[32];
        crypto_core_ed25519_from_uniform(tempHashDigest, vecPK[i-1].pkb);                   // hashDigest = h(pk)
        if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[i].skb, tempHashDigest))
        {
            printf("[-] failed to compute lRi\n");
            return -1;
        }

        if(crypto_scalarmult_ed25519_noclamp(right_Ri, hi, signature->keyImage))
        {
            printf("[-] failed to compute rRi");
            return -1;
        }
        crypto_core_ed25519_add(Ri, left_Ri,right_Ri);
        // computing h_i = H(tx||Li||Ri)
        memcpy(&hashInput[message_len], Li, crypto_core_ed25519_BYTES); 			                     // (tx||Li||0.0)
        memcpy(&hashInput[message_len+crypto_core_ed25519_BYTES], Ri, crypto_core_ed25519_BYTES); // (tx||Li||Ri)
        crypto_hash_sha256(hi, hashInput, inputLength);
        crypto_core_ed25519_scalar_reduce(hi,hi);
    }

    // last step
    crypto_scalarmult_ed25519_base_noclamp(left_Li, signature->scalarPoints[0].skb); // s0*G
    if(crypto_scalarmult_ed25519_noclamp(right_Li, hi, vecPK[ringSize-1].pkb))   // h_{n-1}*pk
    {
        printf("[-] failed to compute Li");
        return -1;
    }
    crypto_core_ed25519_add(Li, left_Li,right_Li);
    // Compute Ri
    uint8_t tempHashDigest[32];
    crypto_core_ed25519_from_uniform(tempHashDigest, vecPK[ringSize-1].pkb);                   // hashDigest = h(pk)
    if(crypto_scalarmult_ed25519_noclamp(left_Ri, signature->scalarPoints[0].skb, tempHashDigest))
    {
        printf("[-] failed to compute lRi\n");
        return -1;
    }

    if(crypto_scalarmult_ed25519_noclamp(right_Ri, hi, signature->keyImage))
    {
        printf("[-] failed to compute rRi");
        return -1;
    }
    crypto_core_ed25519_add(Ri, left_Ri,right_Ri);
    // computing h_i = H(tx||Li||Ri)
    memcpy(&hashInput[message_len], Li, crypto_core_ed25519_BYTES); 			                     // (tx||Li||0.0)
    memcpy(&hashInput[message_len+crypto_core_ed25519_BYTES], Ri, crypto_core_ed25519_BYTES); // (tx||Li||Ri)
    crypto_hash_sha256(hi, hashInput, inputLength);                                                 // h0 = H(tx||L0||R0)
    int answer = memcmp(hi,signature->h0, crypto_core_ed25519_SCALARBYTES);
    return answer; //for valid message
}