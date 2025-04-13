#include "Pseudonym.h"
#include <random>

#include <sodium.h>

#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <string>
#include <cstring>
#include <sstream>
#include <iomanip> 
#include <algorithm> 
#include <iostream>


using namespace std;

#define SEED_SIZE_OPENSSL 32
#define KEY_SIZE_OPENSSL 32
#define SEALED_DATA_SIZE 12 + 32 + 1 //includes de cifred data and the IV, assuming the long has 8bytes. 12 -> IV; 65 -> uid(private key); 1->pq sim
#define SIG_SIZE_OPENSSL 64
#define SGX_AESGCM_IV_SIZE 12
#define long_size 8
#define uid_SIZE 32

class crypto
{
    public:
        static void generatePmKeys(unsigned char* publicKey, unsigned char* privateKey);
        static void getRandomID(unsigned char* uid_priv);
        static void generateKeys(unsigned char* seed, unsigned char* privateKeyOut, unsigned char* publicKeyOut);
        static void get_digest(unsigned char* seed, unsigned char* digest);
        static void pseudo_sign(unsigned char* epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* signature, unsigned char* skpk);
        static bool verify_pseudo_sign(unsigned char* epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* signature, unsigned char* pk);
        static void get_digest(unsigned long epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* digest);
        static void generateRandomSeed(unsigned char* seed);
        static string unsigned_char_to_string(const unsigned char *bytes, int size);
        static void string_to_unsigned_char(const string &str, unsigned char *output);  
        static void generateRevocationProof(const unsigned char* message, size_t message_len, const unsigned char* secret_key, unsigned char* signature);        
        static bool verifyProof(const unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* public_key);
        static bool verifySignBloomFilter(std::stringstream& bitstream, unsigned char* seed, unsigned char* publicKey, unsigned char* signature);
        static void signBloomFilter(std::vector<char>& bloomFilter, long epoch, unsigned char* seed, unsigned char* secretKey, unsigned char* signature);
        static bool verifySignBloomFilter(std::vector<char>& bloomFilter, long epoch, unsigned char* seed, unsigned char* pubKey, unsigned char* signature);
}; 