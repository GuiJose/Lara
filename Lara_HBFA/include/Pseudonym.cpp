// Pseudonym.cpp
#include "Pseudonym.h"
#include <string.h>

Pseudonym::Pseudonym() {
    // Default constructor implementation
}

Pseudonym::Pseudonym(long epoch, const unsigned char sealedData[45], const unsigned char publicKey[32], const unsigned char Sig[64]) {
    // Parameterized constructor implementation
    this->epoch = epoch;
    memcpy(this->sealedData, sealedData, sizeof(this->sealedData));
    memcpy(this->publicKey, publicKey, sizeof(this->publicKey));
    memcpy(this->Sig, Sig, sizeof(this->Sig));
}
