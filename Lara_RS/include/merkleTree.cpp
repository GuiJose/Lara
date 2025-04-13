#include "merkleTree.h"
#include <cmath>
#include <iomanip>
#include <openssl/sha.h>
#include <chrono>
#include <unordered_map>
#include <sstream>
#include <unordered_set>

std::string sha256(const std::string &str)
{
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_state state;

    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char *>(str.c_str()), str.size());
    crypto_hash_sha256_final(&state, hash);

    return std::string(reinterpret_cast<char *>(hash), crypto_hash_sha256_BYTES);
}

std::string sha256(const std::vector<std::string> &str_list)
{
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_state state;

    crypto_hash_sha256_init(&state);

    for (const auto &str : str_list)
    {
        crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char *>(str.c_str()), str.size());
    }

    crypto_hash_sha256_final(&state, hash);

    return std::string(reinterpret_cast<char *>(hash), crypto_hash_sha256_BYTES);
}

void merkleTree::divideIntoPieces(bloomFilter filter, int numberLevels, int pieceSize)
{
    long numberOfPieces;
    if (filter.size % pieceSize == 0)
    {
        numberOfPieces = filter.size / pieceSize;
    }
    else
    {
        numberOfPieces = filter.size / pieceSize + 1;
    }
    for (int i = 0; i < numberOfPieces; i++)
    {
        hashes[numberLevels].push_back(sha256(filter.getPiece(i, pieceSize)));
    }
}

void merkleTree::buildTree(int numLevels)
{
    while (numLevels >= 1)
    {
        std::vector<std::string> &currentLevel = hashes[numLevels];
        std::vector<std::string> &nextLevel = hashes[numLevels - 1];
        int length = currentLevel.size();

        nextLevel.reserve((length + 1) / 2);

        std::string str1 = "";
        for (size_t i = 0; i < length; i += degree)
        {
            str1 = currentLevel[i];
            for (size_t e = 1; e < degree; e++)
            {
                const std::string &str2 = (i + e < length) ? currentLevel[i + e] : "";
                str1 = str1 + str2;
            }
            nextLevel.push_back(sha256(str1));
        }
        numLevels--;
    }
    // print root hash
    std::string hashValue = hashes[0][0];
    std::cout << "Hash: " << hashValue << std::endl;
}

void merkleTree::signRoot(const unsigned char *pmSecretKey)
{
    crypto::signRoot(this->hashes[0][0], this->randomSeed, pmSecretKey, this->rootSignature);
}

merkleTree::merkleTree(bloomFilter filter, int treeDegree, int sizePieces)
{
    this->degree = treeDegree;
    this->piecesSize = sizePieces;

    int levels = 0;
    while (true)
    {
        if (pow(treeDegree, levels) >= (static_cast<double>(filter.size) / sizePieces))
        {
            hashes.push_back({});
            break;
        }
        hashes.push_back({});
        levels++;
    }
    this->numberLevels = levels;

    divideIntoPieces(filter, levels, sizePieces);
    buildTree(levels);

    crypto::generateRandomSeed(this->randomSeed);

    /*int count = 0;
    for (const auto& innerList : hashes) {
        std::cout << "level number : " << count << std::endl;
        int count2 = 0;
        for (const auto& str : innerList) {
            std::cout << "hash number : " << count2 << " ";
            std::cout << str << " ";
            std::cout << std::endl;
            count2++;
        }
        count++;
        std::cout << std::endl;
    }*/
}

merkleTree::merkleTree()
{
}

/*std::vector<std::tuple<int, int, std::string>> merkleTree::piecesToVerify(std::vector<long> piecesRequested, int levels){
    int numberIterations = 0;
    std::vector<std::vector<int>> clientConsegue(levels);
    std::vector<std::tuple<int, int, std::string>> enviar;
    int iterations = levels;

    while (iterations>=1){
        numberIterations++;
        if (iterations == levels){
            int hashes_size = hashes[iterations].size();
            int length = piecesRequested.size();
            for (int i = 0; i < length; i++){
                    numberIterations++;
                int sector = piecesRequested[i] / degree;
                   numberIterations++;

                for (int x = 0; x < degree; x++){
                    bool requested = false;
                        numberIterations++;

                        for (int element : piecesRequested){
                            if (element == sector*this->degree+x){
                                requested = true;
                            }
                        }
                    if (!requested){
                        if((sector*this->degree+x) >= hashes_size){
                            //enviar.push_back(std::make_tuple(iterations, (sector*this->degree+x), ""));
                        }
                        else{
                            enviar.push_back(std::make_tuple(iterations, (sector*this->degree+x), hashes[iterations][(sector*this->degree+x)]));
                        }
                    }
                }
                clientConsegue[iterations-1].push_back(sector);
            }
        }
        else{
            int hashes_size = hashes[iterations].size();
            int length = clientConsegue[iterations].size();
            for (int i = 0; i < length; i++){
                numberIterations++;
                int sector = clientConsegue[iterations][i] / degree;
                for (int x = 0; x < degree; x++){
                    numberIterations++;
                    bool requested = false;
                        for (int element : clientConsegue[iterations]){
                            numberIterations++;
                            if (element == sector*this->degree+x){
                                requested = true;
                            }
                        }
                    if (!requested){
                        if((sector*this->degree+x) >= hashes_size){
                            //enviar.push_back(std::make_tuple(iterations, (sector*this->degree+x), ""));
                        }
                        else{
                            enviar.push_back(std::make_tuple(iterations, (sector*this->degree+x), hashes[iterations][(sector*this->degree+x)]));
                        }
                    }
                }
                clientConsegue[iterations-1].push_back(sector);
            }
        }
        --iterations;
    }

    for (auto it = enviar.begin(); it != enviar.end(); ++it) {
        numberIterations++;
        for (auto jt = std::next(it); jt != enviar.end();) {
            numberIterations++;
            if (*it == *jt) {
                jt = enviar.erase(jt);
            } else {
                ++jt;
            }
        }
    }

    /*for (const auto& tuple : enviar) {
        std::cout << "(" << std::get<0>(tuple) << ", "
                  << std::get<1>(tuple) << ", "
                  << std::get<2>(tuple) << ")" << std::endl;
    }
    std::cout << "iterations done : " << numberIterations << std::endl;*/

// return enviar;
//}*/

/*std::string merkleTree::verify(int levels, int treeDegree, std::vector<std::tuple<int, std::string>>& bitsRequested, std::vector<std::tuple<int, int, std::string>>& hashesReceived){
    int numberIterations = 0;
    std::vector<std::vector<std::tuple<int, std::string>>> hashesCalculated(levels);

    for (auto& tuple : bitsRequested) {
        std::get<1>(tuple) = sha256(std::get<1>(tuple));
    }

    int iterations = levels;
    int lengthHashes = hashesReceived.size();

    // Transform bitsRequested into a hashmap
    std::unordered_map<int, std::string> bitsRequestedMap;
    for (const auto& bit : bitsRequested) {
        int key = std::get<0>(bit);
        std::string value = std::get<1>(bit);
        bitsRequestedMap[key] = value;
    }

    // Transform hashesReceived into a hashmap
    std::unordered_map<int, std::unordered_map<int, std::string>> hashesReceivedMap;
    for (const auto& hash : hashesReceived) {
        int level = std::get<0>(hash);
        int position = std::get<1>(hash);
        std::string hashValue = std::get<2>(hash);

        if (hashesReceivedMap.find(level) == hashesReceivedMap.end()) {
            hashesReceivedMap[level] = std::unordered_map<int, std::string>();
        }
        hashesReceivedMap[level][position] = hashValue;
    }

    while (iterations >= 1) {
        numberIterations++;
        if (iterations == levels) {
            for (const auto& [position, bitHash] : bitsRequestedMap) {
                numberIterations++;
                int sector = position / treeDegree;
                bool alreadyDone = false;

                for (const auto& [sectorKey, hash] : hashesCalculated[iterations - 1]) {
                    if (sectorKey == sector) {
                        alreadyDone = true;
                        break;
                    }
                }

                if (!alreadyDone) {
                    std::string input;
                    for (int x = sector * treeDegree; x < sector * treeDegree + treeDegree; ++x) {
                        numberIterations++;
                        if (bitsRequestedMap.find(x) != bitsRequestedMap.end()) {
                            input += bitsRequestedMap[x];
                        } else if (hashesReceivedMap[iterations].find(x) != hashesReceivedMap[iterations].end()) {
                            input += hashesReceivedMap[iterations][x];
                        }
                    }
                    hashesCalculated[iterations - 1].emplace_back(sector, sha256(input));
                }
            }
        } else {
            for (const auto& hash : hashesCalculated[iterations]) {
                int position = std::get<0>(hash);
                numberIterations++;
                int sector = position / treeDegree;
                bool alreadyDone = false;

                for (const auto& sectorHash : hashesCalculated[iterations - 1]) {
                    if (std::get<0>(sectorHash) == sector) {
                        alreadyDone = true;
                        break;
                    }
                }

                if (!alreadyDone) {
                    std::string input;
                    for (int x = sector * treeDegree; x < sector * treeDegree + treeDegree; ++x) {
                        numberIterations++;
                        auto it = std::find_if(hashesCalculated[iterations].begin(), hashesCalculated[iterations].end(),
                            [x](const std::tuple<int, std::string>& t) { return std::get<0>(t) == x; });
                        if (it != hashesCalculated[iterations].end()) {
                            input += std::get<1>(*it);
                        } else if (hashesReceivedMap[iterations].find(x) != hashesReceivedMap[iterations].end()) {
                            input += hashesReceivedMap[iterations][x];
                        }
                    }
                    hashesCalculated[iterations - 1].emplace_back(sector, sha256(input));
                }
            }
        }
        iterations--;
    }

    // Print calculated hashes for verification
    /*std::cout << "Hashes calculated during verification:\n";
    for (size_t i = 0; i < hashesCalculated.size(); ++i) {
        std::cout << "Level " << i << ":\n";
        for (size_t j = 0; j < hashesCalculated[i].size(); ++j) {
            const auto& hash = hashesCalculated[i][j];
            std::cout << "  Tuple " << j << ": ("
                      << std::get<0>(hash) << ", "
                      << std::get<1>(hash) << ")\n";
        }
    }*/

// std::cout << "Iterations done: " << numberIterations << std::endl;

// Return root hash
// return std::get<1>(hashesCalculated[0][0]);
//}

/*std::string merkleTree::verify(int levels, int treeDegree, std::vector<std::tuple<int, std::string>>& bitsRequested, std::vector<std::tuple<int, int, std::string>>& hashesReceived){
    int numberIterations = 0;
    std::vector<std::vector<std::tuple<int, std::string>>> hashesCalculated(levels);

    for (auto& tuple : bitsRequested) {
        std::get<1>(tuple) = sha256(std::get<1>(tuple));
    }

    int iterations = levels;
    int lengthHashes = hashesReceived.size();

    while (iterations >= 1){
        numberIterations++;
        if (iterations == levels){
            int length = bitsRequested.size();
            for (int i = 0; i < length; i++){
                        numberIterations++;

                int sector = std::get<0>(bitsRequested[i]) / treeDegree;
                int size = hashesCalculated[iterations-1].size();
                bool alreadyDone = false;

                for (int x = 0; x < size; x++){
                    numberIterations++;

                    if (std::get<0>(hashesCalculated[iterations-1][0])==sector){
                        alreadyDone = true;
                    }
                }
                if (!alreadyDone){
                    std::string input = "";
                    for (int x = sector*treeDegree; x<sector*treeDegree+treeDegree; x++){
                                numberIterations++;

                        bool found = false;
                        if (x == std::get<0>(bitsRequested[i])){
                            input += std::get<1>(bitsRequested[i]);
                            found = true;
                        }
                        else{
                            for (auto& tuple : hashesReceived){
                                        numberIterations++;

                                if (std::get<1>(tuple) == x && std::get<0>(tuple) == iterations){
                                    input.append(std::get<2>(tuple));
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (!found){
                            for (int y = 0; y < length; y++){
                                if (x == std::get<0>(bitsRequested[y])){
                                    input.append(std::get<1>(bitsRequested[y]));
                                    break;
                                }
                            }
                        }
                    }
                    hashesCalculated[iterations-1].push_back(std::make_tuple(sector, sha256(input)));
                }
            }
        }
        else{
            int length = hashesCalculated[iterations].size();
            for (int i = 0; i < length; i++){
                        numberIterations++;

                int sector = std::get<0>(hashesCalculated[iterations][i]) / treeDegree;
                int size = hashesCalculated[iterations-1].size();
                bool alreadyDone = false;
                for (int x = 0; x < size; x++){
                            numberIterations++;

                    if (std::get<0>(hashesCalculated[iterations-1][0])==sector){
                        alreadyDone = true;
                    }
                }
                if (!alreadyDone){
                    std::string input = "";
                    for (int x = sector*treeDegree; x<sector*treeDegree+treeDegree; x++){
                                numberIterations++;

                        bool found = false;
                        if (x == std::get<0>(hashesCalculated[iterations][i])){
                            input += std::get<1>(hashesCalculated[iterations][i]);
                            found = true;
                        }
                        else{
                            for (auto& tuple : hashesReceived){
                                        numberIterations++;

                                if (std::get<1>(tuple) == x && std::get<0>(tuple) == iterations){
                                    input.append(std::get<2>(tuple));
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (!found){
                            for (int y = 0; y < length; y++){
                                        numberIterations++;

                                if (x == std::get<0>(hashesCalculated[iterations][y])){
                                    input.append(std::get<1>(hashesCalculated[iterations][y]));
                                    break;
                                }
                            }
                        }
                    }
                    hashesCalculated[iterations-1].push_back(std::make_tuple(sector, sha256(input)));
                }
            }
        }
        iterations--;
    }

    //std::cout << "hashes Calculated during verification" << std::endl;

    //for (size_t i = 0; i < hashesCalculated.size(); ++i) {
      //  std::cout << "Level " << i << ":\n";
        //for (size_t j = 0; j < hashesCalculated[i].size(); ++j) {
          //  const auto& hash = hashesCalculated[i][j];
            //std::cout << "  Tuple " << j << ": ("
              //        << std::get<0>(hash) << ", "
                //      << std::get<1>(hash) << ")\n";
        //}
    //}

    //print root hash
    //std::string hashValue = std::get<1>(hashesCalculated[0][0]);
    //std::cout << "Hash: " << hashValue << std::endl;

    std::cout << "iterations done : " << numberIterations << std::endl;


    return std::get<1>(hashesCalculated[0][0]);
}*/

struct TupleHash
{
    template <typename T>
    inline void hash_combine(std::size_t &seed, const T &v) const
    {
        std::hash<T> hasher;
        seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }

    std::size_t operator()(const std::tuple<int, int, std::string> &t) const
    {
        std::size_t seed = 0;
        hash_combine(seed, std::get<0>(t));
        hash_combine(seed, std::get<1>(t));
        hash_combine(seed, std::get<2>(t));
        return seed;
    }
};

std::vector<std::tuple<int, int, std::string>> merkleTree::piecesToVerify(std::vector<long> piecesRequested, int levels)
{
    std::vector<std::unordered_set<int>> clientConsegue(levels);
    std::vector<std::tuple<int, int, std::string>> enviar;
    int iterations = levels;

    std::unordered_set<int> piecesRequestedSet(piecesRequested.begin(), piecesRequested.end());
    std::unordered_set<std::tuple<int, int, std::string>, TupleHash> enviarSet;

    while (iterations >= 1)
    {
        if (iterations == levels)
        {
            int hashes_size = hashes[iterations].size();
            for (long piece : piecesRequested)
            {
                int sector = piece / degree;
                for (int x = 0; x < degree; x++)
                {
                    int index = sector * degree + x;
                    if (piecesRequestedSet.find(index) == piecesRequestedSet.end())
                    {
                        if (index < hashes_size)
                        {
                            enviarSet.insert(std::make_tuple(iterations, index, hashes[iterations][index]));
                        }
                    }
                }
                clientConsegue[iterations - 1].insert(sector);
            }
        }
        else
        {
            int hashes_size = hashes[iterations].size();
            for (int sector : clientConsegue[iterations])
            {
                int parentSector = sector / degree;
                for (int x = 0; x < degree; x++)
                {
                    int index = parentSector * degree + x;
                    if (clientConsegue[iterations].find(index) == clientConsegue[iterations].end())
                    {
                        if (index < hashes_size)
                        {
                            enviarSet.insert(std::make_tuple(iterations, index, hashes[iterations][index]));
                        }
                    }
                }
                clientConsegue[iterations - 1].insert(parentSector);
            }
        }
        --iterations;
    }

    // Convert set to vector
    for (const auto &entry : enviarSet)
    {
        enviar.push_back(entry);
    }
    return enviar;
}

std::string merkleTree::verify(int levels, int treeDegree, std::vector<std::tuple<int, std::string>> &bitsRequested, std::vector<std::tuple<int, int, std::string>> &hashesReceived)
{
    std::vector<std::unordered_map<int, std::string>> hashesCalculated(levels);

    // Hash all bitsRequested upfront
    for (auto &tuple : bitsRequested)
    {
        std::get<1>(tuple) = sha256(std::get<1>(tuple));
    }

    std::unordered_map<int, std::unordered_map<int, std::string>> receivedMap;
    for (const auto &tuple : hashesReceived)
    {
        receivedMap[std::get<0>(tuple)][std::get<1>(tuple)] = std::get<2>(tuple);
    }

    int iterations = levels;

    while (iterations >= 1)
    {
        if (iterations == levels)
        {
            for (const auto &bit : bitsRequested)
            {
                int sector = std::get<0>(bit) / treeDegree;
                if (hashesCalculated[iterations - 1].find(sector) == hashesCalculated[iterations - 1].end())
                {
                    std::string input;
                    bool sectorFilled = false;
                    for (int x = sector * treeDegree; x < sector * treeDegree + treeDegree; ++x)
                    {
                        if (x == std::get<0>(bit))
                        {
                            input += std::get<1>(bit);
                            sectorFilled = true;
                        }
                        else if (receivedMap[iterations].find(x) != receivedMap[iterations].end())
                        {
                            input += receivedMap[iterations][x];
                            sectorFilled = true;
                        }
                        else
                        {
                            for (const auto &br : bitsRequested)
                            {
                                if (x == std::get<0>(br))
                                {
                                    input += std::get<1>(br);
                                    sectorFilled = true;
                                    break;
                                }
                            }
                        }
                        if (!sectorFilled)
                        {
                            input += "";
                        }
                    }
                    hashesCalculated[iterations - 1][sector] = sha256(input);
                }
            }
        }
        else
        {
            for (const auto &hashPair : hashesCalculated[iterations])
            {
                int sector = hashPair.first / treeDegree;
                if (hashesCalculated[iterations - 1].find(sector) == hashesCalculated[iterations - 1].end())
                {
                    std::stringstream input;
                    bool sectorFilled = false;
                    for (int x = sector * treeDegree; x < sector * treeDegree + treeDegree; ++x)
                    {
                        if (x == hashPair.first)
                        {
                            input << hashPair.second;
                            sectorFilled = true;
                        }
                        else if (receivedMap[iterations].find(x) != receivedMap[iterations].end())
                        {
                            input << receivedMap[iterations][x];
                            sectorFilled = true;
                        }
                        else if (hashesCalculated[iterations].find(x) != hashesCalculated[iterations].end())
                        {
                            input << hashesCalculated[iterations][x];
                            sectorFilled = true;
                        }
                        if (!sectorFilled)
                        {
                            input << "";
                        }
                    }
                    hashesCalculated[iterations - 1][sector] = sha256(input.str());
                }
            }
        }
        iterations--;
    }
    return hashesCalculated[0].begin()->second;
}