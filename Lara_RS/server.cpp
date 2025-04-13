#include <string>
#include "include/bloomFilter.h"
#include "include/merkleTree.h"
#include <cstdint>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>

unsigned char *seed;

// PM keys
unsigned char spkp[crypto_sign_ed25519_SECRETKEYBYTES];
unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

class server
{
public:
  server(int numFilters) : numberOfFilters(numFilters)
  {
  }

  // tenho que enviar o número de filtros, e para cada filtro, "seed" (32 bytes), filterSize(long), numberHashFunctions(int), treeDegree(int), piecesSize(long)
  void sendDetails(int clientSocket)
  {
    long piecesSize = 0;
    unsigned char message[4 + this->numberOfFilters * (32 + 8 + 4 + 4 + 8 + 4 + 64)];
    std::memcpy(message, &this->numberOfFilters, sizeof(int));
    int offset = 4;
    for (int i = 0; i < this->numberOfFilters; i++)
    {
      std::memcpy(message + offset, seed, 32);
      offset += 32;
      std::memcpy(message + offset, &this->filter.size, sizeof(long));
      offset += 8;
      std::memcpy(message + offset, &this->filter.m_numHashes, sizeof(int));
      offset += 4;
      std::memcpy(message + offset, &this->tree.degree, sizeof(int));
      offset += 4;
      std::memcpy(message + offset, &this->tree.piecesSize, sizeof(long));
      offset += 8;
      std::memcpy(message + offset, &this->tree.numberLevels, sizeof(long));
      offset += 4;
      std::memcpy(message + offset, this->tree.rootSignature, 64);
      offset += 64;
    }

    ssize_t bytesSent = send(clientSocket, message, 4 + this->numberOfFilters * (32 + 8 + 4 + 4 + 8 + 4 + 64), 0);
    if (bytesSent == -1)
    {
      std::cerr << "Error: Failed to send numberFilter\n";
      close(clientSocket);
      return; // Indicate failure
    }
  }

  void sendBits(int clientSocket, unsigned char *message)
  {
    long sizeDataToSend = 0;
    std::vector<std::vector<long>> bitsRequested;
    long offset = 4;
    unsigned char sizeOfData2[8];

    for (int i = 0; i < this->numberOfFilters; i++)
    {
      std::vector<long> bits;
      long bit = 0;
      for (int e = 0; e < this->filter.m_numHashes; e++)
      {
        std::memcpy(&bit, message + offset, sizeof(long));
        offset += 8;
        bits.push_back(bit);
      }
      bitsRequested.push_back(bits);
    }

    for (std::vector<long> &x : bitsRequested)
    {
      for (long &bit : x)
      {
        bit = bit / (this->tree.piecesSize);
      }
    }

    std::vector<std::vector<std::tuple<int, int, std::string>>> hashesToSend;
    for (std::vector<long> bits : bitsRequested)
    {
      hashesToSend.push_back(this->tree.piecesToVerify(bits, this->tree.numberLevels));
    }

    std::vector<std::vector<std::tuple<int, std::string>>> piecesToSend;
    for (const std::vector<long> &x : bitsRequested)
    {
      std::vector<std::tuple<int, std::string>> lista;
      std::vector<long> piecesSent;
      for (long bit : x)
      {
        bool alreadySent = false;
        for (long i : piecesSent)
        { // Iterate over piecesSent correctly
          if (bit == i)
          {
            alreadySent = true;
            break;
          }
        }
        if (!alreadySent)
        {
          piecesSent.push_back(bit);
          lista.push_back({bit, this->filter.getPiece(bit, this->tree.piecesSize)});
        }
      }
      piecesToSend.push_back(lista);
    }

    /*for (const auto& innerVec : piecesToSend) {
        for (const auto& tuple : innerVec) {
            std::cout << "(" << std::get<0>(tuple) << ", " << std::get<1>(tuple) << ") ";
        }
        std::cout << std::endl;
    }

    for (const auto& innerVec : hashesToSend) {
        for (const auto& tuple : innerVec) {
            std::cout << "(" << std::get<0>(tuple) << ", " << std::get<1>(tuple) << ", " << std::get<2>(tuple) << ") ";
        }
        std::cout << std::endl;
    }*/

    // Calculate message size
    long totalMessageSize = 0;
    int piecesSize;
    if (this->tree.piecesSize % 8 == 0)
    {
      piecesSize = this->tree.piecesSize / 8;
    }
    else
    {
      piecesSize = (this->tree.piecesSize / 8) + 1;
    }

    for (const auto &vec : piecesToSend)
    {
      for (const auto &tpl : vec)
      {
        totalMessageSize += 4 + piecesSize;
      }
      totalMessageSize += 4;
    }
    for (const auto &vec : hashesToSend)
    {
      for (const auto &tpl : vec)
      {
        totalMessageSize += 4 + 4 + 32;
      }
      totalMessageSize += 4;
    }

    unsigned char dataToSend[totalMessageSize];
    offset = 0;
    // Colocar os pieces.
    for (const auto &vec : piecesToSend)
    {
      int count = 0;
      for (const auto &tpl : vec)
      {
        count++;
      }
      // Copy the count of pieces into the vector
      std::memcpy(dataToSend + offset, &count, sizeof(int));
      offset += sizeof(int); // Update offset
      for (const auto &tpl : vec)
      {
        unsigned char piece[piecesSize];
        int pieceNumber = std::get<0>(tpl);
        crypto::string_to_unsigned_char(std::get<1>(tpl), piece);
        std::memcpy(dataToSend + offset, &pieceNumber, sizeof(int));
        offset += sizeof(int); // Update offset
        std::memcpy(dataToSend + offset, piece, piecesSize);
        offset += piecesSize; // Update offset
      }
    }

    // Colocar os hashes.
    for (const auto &vec : hashesToSend)
    {
      int count = 0;
      for (const auto &tpl : vec)
      {
        count++;
      }
      std::memcpy(dataToSend + offset, &count, sizeof(int));
      offset += sizeof(int); // Update offset
      for (const auto &tpl : vec)
      {
        int numberLevel = std::get<0>(tpl);
        int numberHash = std::get<1>(tpl);
        unsigned char hash[32];
        crypto::string_to_unsigned_char(std::get<2>(tpl), hash);
        std::memcpy(dataToSend + offset, &numberLevel, sizeof(int));
        offset += sizeof(int); // Update offset
        std::memcpy(dataToSend + offset, &numberHash, sizeof(int));
        offset += sizeof(int); // Update offset
        std::memcpy(dataToSend + offset, hash, 32);
        offset += 32; // Update offset
      }
    }

    // Send the size of the data to send
    std::memcpy(sizeOfData2, &totalMessageSize, sizeof(totalMessageSize));

    ssize_t bytesSent = send(clientSocket, sizeOfData2, 8, 0);
    if (bytesSent == -1)
    {
      std::cerr << "Error: Failed to send joined data size\n";
    }

    // Send the joined data to the client
    bytesSent = send(clientSocket, dataToSend, totalMessageSize, 0);
    if (bytesSent == -1)
    {
      std::cerr << "Error: Failed to send joined data\n";
    }
  }

  void sendFinalResponse(int clientSocket, unsigned char *message)
  {
    unsigned char epoch2[sizeof(int)];
    unsigned char publicKey[32];
    unsigned char ciphertext[48 + crypto_aead_aes256gcm_ABYTES];
    unsigned char PMsignature[64];
    unsigned char NonRevocationProof[64];

    int offset = 4;
    memcpy(epoch2, message + offset, sizeof(int));
    offset += sizeof(int);
    memcpy(publicKey, message + offset, sizeof(publicKey));
    offset += sizeof(publicKey);
    memcpy(ciphertext, message + offset, sizeof(ciphertext));
    offset += sizeof(ciphertext);
    memcpy(PMsignature, message + offset, sizeof(PMsignature));
    offset += sizeof(PMsignature);

    // Verificar que o pseudonimo foi feito pelo PM
    bool pseudonymOk = crypto::verify_pseudo_sign(epoch2, ciphertext, publicKey, PMsignature, pk);

    bool isInFilter = false;
    bool isOk = false;
    for (int i = 0; i < this->numberOfFilters; i++)
    {
      memcpy(NonRevocationProof, message + offset, sizeof(NonRevocationProof));
      offset += sizeof(NonRevocationProof);
      isInFilter = this->filter.possiblyContains(NonRevocationProof, 64);
      if (isInFilter)
      {
        break;
      }
      isOk = crypto::verifyProof(NonRevocationProof, seed, 32, publicKey);
      // std::cout << "a prova está bem construida? = " << isOk << std::endl;
      if (isOk)
      {
        break;
      }
    }

    // std::cout << "esta no filtro bloom ? = " << isInFilter << std::endl;
    // std::cout << "is well constructed ? = " << isOk << std::endl;
    // std::cout << "termo de comparação " << true << std::endl;

    if (isOk && !isInFilter && pseudonymOk)
    {
      // If verification is successful, send "true" to the client
      // std::cout << "posso deixar o cliente autenticar-se" << std::endl;
      send(clientSocket, "true", strlen("true"), 0);
    }
    else
    {
      // If verification fails, send "false" to the client
      // std::cout << " não posso deixar o cliente autenticar-se" << std::endl;
      send(clientSocket, "false", strlen("false"), 0);
    }
  }

  void createFilterBloom(long size, int numberHashFunctions)
  {
    bloomFilter filter2(size, numberHashFunctions);
    filter = filter2;
  }

  void createMerkleTree(int treeDegree, int sizePieces)
  {
    tree = merkleTree(filter, treeDegree, sizePieces);
  }

  void RunServer()
  {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
      std::cerr << "Error: Socket creation failed\n";
      return;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP address
    serverAddr.sin_port = htons(50051);      // Use port 50051
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      std::cerr << "Error: Bind failed\n";
      close(serverSocket);
      return;
    }

    if (listen(serverSocket, 5) == -1)
    {
      std::cerr << "Error: Listen failed\n";
      close(serverSocket);
      return;
    }

    std::cout << "Server listening on port: " << serverAddr.sin_port << std::endl;

    while (true)
    {
      // Accept a client connection
      struct sockaddr_in clientAddr;
      socklen_t clientAddrLen = sizeof(clientAddr);
      int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
      if (clientSocket == -1)
      {
        std::cerr << "Error: Accept failed\n";
        close(serverSocket);
        return;
      }
      // std::cout << "Connection established with client\n";
      //  Receive a message from the client
      unsigned char message[5000];
      ssize_t bytesReceived = recv(clientSocket, message, sizeof(message), 0);
      if (bytesReceived <= 0)
      {
        std::cerr << "Error: Failed to receive message from client\n";
        close(clientSocket);
        continue; // Continue to accept next connection
      }

      unsigned int messageId = 0;
      std::memcpy(&messageId, message, 4);

      if (messageId == 1)
      {
        // std::cout << "Received a message with id 1" << std::endl;
        sendDetails(clientSocket);
      }
      else if (messageId == 2)
      {
        // std::cout << "Received a message with id 2" << std::endl;
        sendBits(clientSocket, message);
      }
      else
      {
        // std::cout << "Received a message with id 3" << std::endl;
        sendFinalResponse(clientSocket, message);
      }
      close(clientSocket);
    }
    close(serverSocket);
  }

public:
  bloomFilter filter;
  merkleTree tree;
  int numberOfFilters;
};

// ./server number_of_filters filter_size filter_number_functions tree_degree size_pieces
int main(int argc, char **argv)
{

  int numberOfFilters = std::stoi(argv[1]);
  long size = std::stol(argv[2]);
  int numberHashFunctions = std::stoi(argv[3]);
  int treeDegree = std::stoi(argv[4]);
  int sizePieces = std::stoi(argv[5]);

  crypto::generatePmKeys(pk, spkp);

  server myServer(numberOfFilters);

  myServer.createFilterBloom(size, numberHashFunctions);
  myServer.createMerkleTree(treeDegree, sizePieces);
  myServer.tree.signRoot(spkp);
  seed = myServer.tree.randomSeed;

  // std::vector<std::tuple<int, int, std::string>> enviar;
  // enviar = myServer.tree.piecesToVerify({1,2,7}, myServer.tree.numberLevels);
  //  std::vector<std::tuple<int, std::string>> bitsRequested = {std::make_tuple(1, myServer.filter.getBitsInRange(1000, 1999)), std::make_tuple(2, myServer.filter.getBitsInRange(2000, 2999)), std::make_tuple(7, myServer.filter.getBitsInRange(7000, 7999))};
  //  merkleTree::verify(myServer.tree.numberLevels, myServer.tree.degree, bitsRequested, enviar);
  myServer.RunServer();

  return 0;
}