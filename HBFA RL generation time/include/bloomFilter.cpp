#include "bloomFilter.h"
#include <sodium.h>

std::array<uint64_t, 2> hashBF(const uint8_t *data,
                               std::size_t len)
{
    std::array<uint64_t, 2> hashValue;
    MurmurHash3_x64_128(data, len, 0, hashValue.data());
    return hashValue;
}

std::array<uint8_t, 32> sha256Hash(const uint8_t *data, std::size_t len)
{
    std::array<uint8_t, 32> hashOutput;
    crypto_hash_sha256(hashOutput.data(), data, len);
    return hashOutput;
}

inline uint64_t nthHash(uint8_t n,
                        uint64_t hashA,
                        uint64_t hashB,
                        uint64_t filterSize)
{
    // cout << "\n(" << hashA << " + " << (int)n  << "*" << hashB << ") % " << filterSize << "  ==  (" << hashA + n * hashB<< ") % " <<filterSize << " = " << (hashA + n * hashB) % filterSize ;

    return (hashA + n * hashB) % filterSize;
}

bloomFilter::bloomFilter() : m_numHashes(0), size(0) {}

bloomFilter::bloomFilter(uint64_t size, uint8_t numHashes) : m_numHashes(numHashes), size(size)
{
    long numBytes = size / 8;
    int rest = size % 8;
    if (rest == 0)
    {
        bitArray = std::vector<char>(numBytes);
    }
    else
    {
        bitArray = std::vector<char>(numBytes + 1);
    }
}

void bloomFilter::add(unsigned char *data, std::size_t len)
{
    std::array<uint8_t, 32> shaHash = sha256Hash(data, len);
    std::array<uint64_t, 2> hashValues = hashBF(shaHash.data(), shaHash.size());

    for (int n = 0; n < m_numHashes; n++)
    {
        std::size_t index = nthHash(n, hashValues[0], hashValues[1], size);
        std::size_t byteIndex = index / 8;
        int bitOffset = index % 8;
        bitArray[byteIndex] |= (1 << bitOffset);
    }
}

bool bloomFilter::possiblyContains(unsigned char *data, std::size_t len) const
{
    std::array<uint8_t, 32> shaHash = sha256Hash(data, len);
    std::array<uint64_t, 2> hashValues = hashBF(shaHash.data(), shaHash.size());

    for (int n = 0; n < m_numHashes; n++)
    {
        int64_t index = nthHash(n, hashValues[0], hashValues[1], size);
        int64_t byteIndex = index / 8;
        int bitOffset = index % 8;
        if ((bitArray[byteIndex] & (1 << bitOffset)) == 0)
        {
            return false;
        }
    }
    return true;
}

std::vector<int64_t> clientBits(long length, int hashes, const uint8_t *proof)
{
    std::array<uint8_t, 32> shaHash = sha256Hash(proof, 64);
    std::array<uint64_t, 2> hashValues = hashBF(shaHash.data(), shaHash.size());

    std::vector<int64_t> bits;
    for (int n = hashes - 1; n >= 0; n--)
    {
        bits.push_back(nthHash(n, hashValues[0], hashValues[1], length));
    }
    std::sort(bits.begin(), bits.end());
    return bits;
}

std::string bloomFilter::getBitsInRange(std::size_t start, std::size_t end, long piecesSize)
{
    std::string result;
    char currentChar = 0;
    int bitCount = 0;
    int resultLength;
    if (piecesSize % 8 == 0)
    {
        resultLength = piecesSize / 8;
    }
    else
    {
        resultLength = piecesSize / 8 + 1;
    }

    // Iterate over the range of bits and construct the result string
    for (std::size_t i = start; i < end; ++i)
    {
        std::size_t byteIndex = i / 8;
        int bitOffset = i % 8;

        if (byteIndex >= this->size / 8)
        {
            break;
        }

        // Check the bit at the specified index within the current char
        if (bitArray[byteIndex] & (1 << bitOffset))
        {
            currentChar |= (1 << bitCount);
        }
        bitCount++;
        // If we have accumulated 8 bits, append the character to the result string
        if (bitCount == 8)
        {
            result += currentChar;
            currentChar = 0;
            bitCount = 0;
        }
    }
    // If there are remaining bits that do not form a complete byte, append them as well
    if (bitCount > 0)
    {
        result += currentChar;
    }

    currentChar = 0;
    for (int i = result.size(); i < resultLength; i++)
    {
        result += currentChar;
    }

    // std::cout << "end : " << end << std::endl;
    // std::cout << "tamanho do filtro : " << this->size << std::endl;
    // std::cout << "tamanho do result : " << result.size() << std::endl;
    // std::cout << "result : " << result << std::endl;
    return result;
}

std::string bloomFilter::getPiece(long piece, long piecesSize)
{
    return getBitsInRange(piece * piecesSize, (piece + 1) * piecesSize, piecesSize);
}

std::vector<char> bloomFilter::getBits()
{
    return bitArray;
}
