// Pseudonym.h
#ifndef PSEUDONYM_H
#define PSEUDONYM_H

#include <sodium.h>

class Pseudonym {
public:
    Pseudonym(); // Default constructor
    Pseudonym(long epoch, const unsigned char sealedData[45], const unsigned char publicKey[32], const unsigned char Sig[64]); // Parameterized constructor
    long epoch;
    unsigned char sealedData[48 + crypto_aead_aes256gcm_ABYTES];
    unsigned char publicKey[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char Sig[64];
};

#endif // PSEUDONYM_H