#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <fstream>
#include <openssl/sha.h>
#include "include/bloomFilter.h"

std::vector<uint8_t> generateToken(size_t length = 32)
{
    std::vector<uint8_t> token(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);

    for (auto &byte : token)
    {
        byte = dis(gen);
    }

    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(token.data(), token.size(), hash.data());
    return hash;
}

void runExperiment(std::ofstream &outputFile, uint64_t filterSize, uint8_t numHashes)
{
    // std::vector<int> numFilters = {1, 5, 10, 20}; 1º run
    // std::vector<int> numTokens = {1000, 10000, 100000, 1000000, 10000000}; 1º run

    std::vector<int> numFilters = {5, 10};
    std::vector<int> numTokens = {50000, 500000, 5000000, 50000000};

    bloomFilter bloomFilter(filterSize, numHashes);
    auto token = generateToken();

    for (int filters : numFilters)
    {
        for (int tokens : numTokens)
        {
            int numRuns = std::max(5, 10000 / tokens);
            double totalDuration = 0.0;
            for (int run = 0; run < numRuns; run++)
            {
                auto start = std::chrono::high_resolution_clock::now();
                for (int j = 2; j < filters; j++)
                {
                    for (int i = 0; i < tokens; i++)
                    {
                        bloomFilter.add(token.data(), token.size());
                    }
                }
                auto end = std::chrono::high_resolution_clock::now();
                totalDuration += std::chrono::duration<double, std::milli>(end - start).count();
            }

            double avgDuration = totalDuration / numRuns;
            outputFile << filters << "," << tokens << "," << filterSize << "," << (int)numHashes << "," << avgDuration << "\n";
            outputFile.flush();

            std::cout << "Completed: Filters = " << filters
                      << ", Tokens = " << tokens
                      << ", Filter Size = " << filterSize
                      << " bytes, Hashes = " << (int)numHashes
                      << ", Runs = " << numRuns
                      << ", Avg Time = " << avgDuration << " ms" << std::endl;
        }
    }
}

int main()
{
    std::ofstream outputFile("experiment_results.csv", std::ios::out | std::ios::trunc);
    if (!outputFile.is_open())
    {
        std::cerr << "Error: Could not open file for writing." << std::endl;
        return 1;
    }

    outputFile << "NumFilters,NumTokens,FilterSize,NumHashes,Time(ms)\n";

    // std::vector<uint64_t> filterSizes = {800000, 8000000, 80000000, 800000000, 8000000000};
    std::vector<uint64_t> filterSizes = {800000, 8000000, 80000000, 800000000};
    std::vector<uint8_t> hashCounts = {5, 10};

    for (auto size : filterSizes)
    {
        for (auto numHashes : hashCounts)
        {
            runExperiment(outputFile, size, numHashes);
        }
    }

    outputFile.close();
    std::cout << "Experiment results saved to 'experiment_results.csv'" << std::endl;
    return 0;
}