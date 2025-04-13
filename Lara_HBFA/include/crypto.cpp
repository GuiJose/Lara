#include "crypto.h"

void crypto::get_digest(unsigned char* seed, unsigned char* digest){
	crypto_hash_sha256(digest, seed, strlen(reinterpret_cast<const char*>(seed)));
}

void crypto::get_digest(unsigned long epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* digest){
    // Create a buffer to hold the data to be hashed
    unsigned char data[sizeof(epoch) + strlen(reinterpret_cast<const char*>(sealedData)) + strlen(reinterpret_cast<const char*>(publicKey))];
        
    // Copy the data into the buffer
    memcpy(data, &epoch, sizeof(epoch));
    memcpy(data + sizeof(epoch), sealedData, strlen(reinterpret_cast<const char*>(sealedData)));
    memcpy(data + sizeof(epoch) + strlen(reinterpret_cast<const char*>(sealedData)), publicKey, strlen(reinterpret_cast<const char*>(publicKey)));

    // Calculate the hash
    crypto_hash_sha256(digest, data, sizeof(data));
}

void crypto::generatePmKeys(unsigned char* publicKey, unsigned char* privateKey) {
    const unsigned char seed[32] = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK";
    crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
}

void crypto::generateKeys(unsigned char* seed, unsigned char* privateKeyOut, unsigned char* publicKeyOut) {
    unsigned char* hash;
    get_digest(seed, hash);
    crypto_sign_ed25519_seed_keypair(publicKeyOut, privateKeyOut, hash);
}

void crypto::pseudo_sign(unsigned char* epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* signature, unsigned char* skpk) {
    unsigned char data[strlen(reinterpret_cast<const char*>(epoch)) + strlen(reinterpret_cast<const char*>(sealedData)) + strlen(reinterpret_cast<const char*>(publicKey))];
    memcpy(data, epoch, strlen(reinterpret_cast<const char*>(epoch)));
    memcpy(data + strlen(reinterpret_cast<const char*>(epoch)), sealedData, strlen(reinterpret_cast<const char*>(sealedData)));
    memcpy(data + strlen(reinterpret_cast<const char*>(epoch)) + strlen(reinterpret_cast<const char*>(sealedData)), publicKey, strlen(reinterpret_cast<const char*>(publicKey)));
    crypto_sign_detached(signature, NULL, data, 32, skpk);
}

bool crypto::verify_pseudo_sign(unsigned char* epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* signature, unsigned char* pk) {
    unsigned char data[strlen(reinterpret_cast<const char*>(epoch)) + strlen(reinterpret_cast<const char*>(sealedData)) + strlen(reinterpret_cast<const char*>(publicKey))];
    memcpy(data, epoch, strlen(reinterpret_cast<const char*>(epoch)));
    memcpy(data + strlen(reinterpret_cast<const char*>(epoch)), sealedData, strlen(reinterpret_cast<const char*>(sealedData)));
    memcpy(data + strlen(reinterpret_cast<const char*>(epoch)) + strlen(reinterpret_cast<const char*>(sealedData)), publicKey, strlen(reinterpret_cast<const char*>(publicKey)));
    return crypto_sign_verify_detached(signature, data, 32, pk) == 0;
}

void crypto::generateRevocationProof(const unsigned char* message, size_t message_len, const unsigned char* secret_key, unsigned char* signature) {
    crypto_sign_detached(signature, NULL, message, message_len, secret_key);
}

// Function to validate a signature
bool crypto::verifyProof(const unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* public_key) {
    return crypto_sign_verify_detached(signature, message, message_len, public_key) == 0;
}

void crypto::generateRandomSeed(unsigned char* seed) {
    std::random_device rd;
    std::mt19937_64 gen(rd()); 

    for (size_t i = 0; i < 32; ++i) {
        seed[i] = static_cast<unsigned char>(gen() & 0xFF);
    }
}

void crypto::signBloomFilter(std::vector<char>& bloomFilter, long epoch, unsigned char* seed, unsigned char* secretKey, unsigned char* signature) {
    int chunkSize = 2000;
    unsigned char hash[crypto_hash_sha256_BYTES]; // Buffer to hold intermediate hash
    crypto_hash_sha256_state state; // SHA-256 state object
        
    crypto_hash_sha256_init(&state);
        
    // Process the bloom filter in chunks
    for (size_t i = 0; i < bloomFilter.size(); i += chunkSize) {
        size_t chunkEnd = std::min(i + chunkSize, bloomFilter.size());
        const std::vector<char> chunk(bloomFilter.begin() + i, bloomFilter.begin() + chunkEnd);
        crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
    }

    crypto_hash_sha256_final(&state, hash);

    // Prepare concatenated data for final hashing
    unsigned char concatenatedHash[crypto_hash_sha256_BYTES + crypto_hash_sha256_BYTES + sizeof(epoch)];
    std::memcpy(concatenatedHash, hash, crypto_hash_sha256_BYTES);
    std::memcpy(concatenatedHash + crypto_hash_sha256_BYTES, seed, crypto_hash_sha256_BYTES);
    std::memcpy(concatenatedHash + crypto_hash_sha256_BYTES + crypto_hash_sha256_BYTES, &epoch, sizeof(epoch));

    // Perform final SHA-256 hashing
    unsigned char finalHash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(finalHash, concatenatedHash, sizeof(concatenatedHash));

    // Sign the final hash with the secret key
    crypto_sign_detached(signature, NULL, finalHash, crypto_hash_sha256_BYTES, secretKey); 
}

bool crypto::verifySignBloomFilter(std::vector<char>& bloomFilter, long epoch, unsigned char* seed, unsigned char* pubKey, unsigned char* signature) {
    int chunkSize = 2000;
    unsigned char hash[crypto_hash_sha256_BYTES]; // Buffer to hold intermediate hash
    crypto_hash_sha256_state state; // SHA-256 state object
        
    crypto_hash_sha256_init(&state);
        
    // Process the bloom filter in chunks
    long bloomFilterSize = bloomFilter.size();
    for (size_t i = 0; i < bloomFilterSize; i += chunkSize) {
        size_t chunkEnd = std::min(i + chunkSize, bloomFilter.size());
        const std::vector<char> chunk(bloomFilter.begin() + i, bloomFilter.begin() + chunkEnd);
        crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
    }

    crypto_hash_sha256_final(&state, hash);
    
    // Prepare concatenated data for final hashing
    unsigned char concatenatedHash[crypto_hash_sha256_BYTES + crypto_hash_sha256_BYTES + sizeof(epoch)];
    std::memcpy(concatenatedHash, hash, crypto_hash_sha256_BYTES);
    std::memcpy(concatenatedHash + crypto_hash_sha256_BYTES, seed, crypto_hash_sha256_BYTES);
    std::memcpy(concatenatedHash + crypto_hash_sha256_BYTES + crypto_hash_sha256_BYTES, &epoch, sizeof(epoch));

    // Perform final SHA-256 hashing
    unsigned char finalHash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(finalHash, concatenatedHash, sizeof(concatenatedHash));

    return crypto_sign_verify_detached(signature, finalHash, crypto_hash_sha256_BYTES, pubKey) == 0;
}


string crypto::unsigned_char_to_string(const unsigned char *bytes, int size) {
    stringstream ss;
    for (int i = 0; i < size; i++) {
        ss << static_cast<char>(bytes[i]);
    }
    return ss.str();
}

void crypto::string_to_unsigned_char(const string &str, unsigned char *output) {
    for (size_t i = 0; i < str.length(); ++i) {
        output[i] = static_cast<unsigned char>(str[i]);
    }
}