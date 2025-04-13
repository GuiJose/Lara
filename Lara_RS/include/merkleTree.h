#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <iostream>
#include <vector>
#include <string>

#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "bloomFilter.h"
#include "crypto.h"

class merkleTree {
private:
    long numberLeaves;

public:
    int numberLevels;
    unsigned char randomSeed[32];
    int degree;
    std::vector<std::vector<std::string>> hashes;
    unsigned char rootSignature[64];
    long piecesSize;

    void signRoot(const unsigned char* pmSecretKey);
    merkleTree();
    merkleTree(bloomFilter filter, int treeDegree, int sizePieces);
    void divideIntoPieces(bloomFilter filter, int numberLevels, int pieceSize);
    void buildTree(int levels);
    std::vector<std::tuple<int, int, std::string>> piecesToVerify(std::vector<long> piecesRequested, int levels);
    static std::string verify(int levels, int treeDegree, std::vector<std::tuple<int, std::string>>& bitsRequested, std::vector<std::tuple<int, int, std::string>>& hashesReceived);
};

#endif