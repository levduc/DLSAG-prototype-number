#include <string.h>
#include <chrono>
#include "../include/lsag.h"
#include "../include/dlsag.h"
#include "../include/helper.h"
#include <iomanip>
#define MESSAGE_LEN 32
using namespace std;
using namespace std::chrono;
int main(void)
{
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        return -1;
    }
    /*generate lsag keypair*/
    // (sk,pk) <- lsag_keygen()
    //LSAG//
    struct lsag_keyPair keyPair;
    lsag_keygen(&keyPair);
    // change ringSize here
    for(int ringSize = 5; ringSize <= 20; ringSize+=5)
    {
        struct edPK vecPK[ringSize];
        /*set vecPK[ringSize-1] = pk*/
        memcpy(vecPK[ringSize-1].pkb, keyPair.lsag_pk, crypto_core_ed25519_BYTES);
        lsag_gen_garbage_PKs(vecPK, ringSize);
        struct lsag_signature signature;
        uint8_t message[MESSAGE_LEN];
        memset(message, 1, MESSAGE_LEN);
        auto start = high_resolution_clock::now();
        for(int i=0; i < 1000; i++)
        {
            if(lsag_sign(&signature, &keyPair, message, MESSAGE_LEN, ringSize,vecPK) < 0)
            {
                printf("[-] Signing failed");
            }
        }
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        cout << "LSAG Ring size:"    << ringSize << endl;
        cout << "\t[+] Signing Time: " << duration.count()/1000000.0<< " ms" << endl;
        start = high_resolution_clock::now();
        for(int i=0; i < 1000; i++)
        {
            if(lsag_verify(&signature, message, MESSAGE_LEN, ringSize,vecPK) != 0)
            {
                printf("[-] Verification failed");
            }
        }
        stop = high_resolution_clock::now();
        auto vertime = duration_cast<microseconds>(stop - start);
        cout << "\t[+] Verifying Time: " << vertime.count()/1000000.0<< " ms" <<endl;
    }

    struct dlsag_keyPair dlsag_keyPair;
    dlsag_keygen(&dlsag_keyPair);
    // change ringSize here
    for(int ringSize = 5; ringSize <= 20; ringSize+=5)
    {
        struct dlsagPK dvecPK[ringSize];
        /*set vecPK[ringSize-1] = pk*/
        memcpy(dvecPK[ringSize-1].pkb0, dlsag_keyPair.dlsag_pk0, crypto_core_ed25519_BYTES);
        memcpy(dvecPK[ringSize-1].pkb1, dlsag_keyPair.dlsag_pk1, crypto_core_ed25519_BYTES);
        dlsag_gen_garbage_PKs(dvecPK, ringSize);
        struct dlsag_signature signature;
        uint8_t message[MESSAGE_LEN];
        memset(message, 1, MESSAGE_LEN);
        auto start = high_resolution_clock::now();
        for(int i=0; i < 1000; i++)
        {
            if(dlsag_sign(&signature, &dlsag_keyPair, message, MESSAGE_LEN, ringSize,dvecPK, true) < 0)
            {
                printf("[-] Signing failed");
            }
        }
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        cout << "DLSAG Ring size:"    << ringSize << endl;
        cout << "\t[+] Signing Time: " << duration.count()/1000000.0<< " ms" << endl;
        start = high_resolution_clock::now();
        for(int i=0; i < 1000; i++)
        {
            if(dlsag_verify(&signature, message, MESSAGE_LEN, ringSize, dvecPK) != 0)
            {
                printf("[-] Verifying failed");
            }
        }
        stop = high_resolution_clock::now();
        auto vertime = duration_cast<microseconds>(stop - start);
        cout << "\t[+] Verifying Time: " << vertime.count()/1000000.0<< " ms" <<endl;
    }
    return 0;
}
