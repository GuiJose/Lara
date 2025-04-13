#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <vector>
#include <cstdint>
#include <functional>
#include <cmath>
#include <iostream>
#include <algorithm>
#include "MurmurHash3.h"

class bloomFilter
{
    public:
        bloomFilter();
        bloomFilter(uint64_t size, uint8_t numHashes);
        void add(unsigned char *data, std::size_t len);
        bool possiblyContains(unsigned char *data, std::size_t len) const;
        std::vector<char> getBits();
        int m_numHashes;
        std::string getBitsInRange(std::size_t start, std::size_t length, long piecesSize);
        std::string getPiece(long piece, long piecesSize);
        long size;
        //std::vector<bool> m_bits;    
        std::vector<char> bitArray;
}; 

std::vector<int64_t> clientBits(long lenght, int hashes, const uint8_t* proof);

#endif // BLOOMFILTER_H