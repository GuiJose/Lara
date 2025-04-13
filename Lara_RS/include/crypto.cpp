#include "crypto.h"

void crypto::get_digest(unsigned char* seed, unsigned char* digest){
	crypto_hash_sha256(digest, seed, strlen(reinterpret_cast<const char*>(seed)));
}

void crypto::get_digest(unsigned char* epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* digest){
    // Create a buffer to hold the data to be hashed
    unsigned char data[strlen(reinterpret_cast<const char*>(epoch)) + strlen(reinterpret_cast<const char*>(sealedData)) + strlen(reinterpret_cast<const char*>(publicKey))];
        
    // Copy the data into the buffer
    memcpy(data, epoch, strlen(reinterpret_cast<const char*>(epoch)));
    memcpy(data + strlen(reinterpret_cast<const char*>(epoch)), sealedData, strlen(reinterpret_cast<const char*>(sealedData)));
    memcpy(data + strlen(reinterpret_cast<const char*>(epoch)) + strlen(reinterpret_cast<const char*>(sealedData)), publicKey, strlen(reinterpret_cast<const char*>(publicKey)));

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
    unsigned char data[4 + 64 + 32];
    memcpy(data, epoch, 4);
    memcpy(data + 4, sealedData, 64);
    memcpy(data + 4 + 64, publicKey, 32);
    crypto_sign_detached(signature, NULL, data, 32, skpk);
}

bool crypto::verify_pseudo_sign(unsigned char* epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* signature, unsigned char* pk) {
    unsigned char data[4 + 64 + 32];
    memcpy(data, epoch, 4);
    memcpy(data + 4, sealedData, 64);
    memcpy(data + 4 + 32, publicKey, 32);
    return crypto_sign_verify_detached(signature, data, 32, pk) == 0;
}

void crypto::generateRevocationProof(const unsigned char* message, size_t message_len, const unsigned char* secret_key, unsigned char* signature) {
    crypto_sign_detached(signature, NULL, message, message_len, secret_key);
}

void crypto::signRoot(std::string root, unsigned char* randomSeed, const unsigned char* pmSecretKey, unsigned char* signature){
    size_t total_length = root.length() + 32;
    unsigned char* concatenated_buffer = new unsigned char[total_length];
    std::memcpy(concatenated_buffer, root.c_str(), root.length());
    std::memcpy(concatenated_buffer + root.length(), randomSeed, 32);

    unsigned char* hashBuffer = new unsigned char[crypto_hash_sha256_BYTES];

    crypto_hash_sha256(hashBuffer, concatenated_buffer, total_length);

    crypto_sign_detached(signature, NULL, hashBuffer, crypto_hash_sha256_BYTES, pmSecretKey);

    delete[] concatenated_buffer;
}

bool crypto::verifyRootSignature(std::string root, unsigned char* randomSeed, const unsigned char* pmPublicKey, unsigned char* signature){
    size_t total_length = root.length() + 32;
    unsigned char* concatenated_buffer = new unsigned char[total_length];
    std::memcpy(concatenated_buffer, root.c_str(), root.length());
    std::memcpy(concatenated_buffer + root.length(), randomSeed, 32);

    unsigned char* hashBuffer = new unsigned char[crypto_hash_sha256_BYTES];

    crypto_hash_sha256(hashBuffer, concatenated_buffer, total_length);
    delete[] concatenated_buffer;

    return crypto_sign_verify_detached(signature, hashBuffer, crypto_hash_sha256_BYTES, pmPublicKey) == 0;
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

void crypto::generateRandomUid(unsigned char* uid) {
    std::random_device rd;
    std::mt19937_64 gen(rd()); 

    for (size_t i = 0; i < 31; ++i) {
        uid[i] = static_cast<unsigned char>(gen() & 0xFF);
    }
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