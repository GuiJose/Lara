#include <string>
#include <fstream>
#include <iostream>
#include "include/Pseudonym.h"
#include "include/crypto.h"
#include "include/bloomFilter.h"
#include "include/merkleTree.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <list> // Include necessary header files
using namespace std;

struct listDetails
{
  unsigned char seed[32];
  unsigned char pmsignature[64];
  int numberHashes;
  int treeDegree;
  long filterSize;
  long piecesSize;
  int treeLevels;
};

std::vector<listDetails> listOfFiltersDetails; // Define an empty vector
std::vector<std::vector<unsigned char>> nonRevocationProofs;

// PM keys
unsigned char spkp[crypto_sign_ed25519_SECRETKEYBYTES];
unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

long numberBytes = 0;

class Client
{
public:
  Client()
  {
    epoch = 1;
    number_pseudonyms = 0;
  }

  void admin_get_pseudonym()
  { // this fuction should comunicate with the pseudonym manager, but for evaluation porpuses only we generate the pseudonum localy
    unsigned char uid[32];
    crypto::generateRandomUid(uid);
    this->number_pseudonyms = this->number_pseudonyms + 1;
    unsigned char sealedData2[64] = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK";
    Pseudonym pseudonym2;
    memcpy(pseudonym2.sealedData, sealedData2, sizeof(sealedData2));

    unsigned char epoch2[sizeof(long)];
    std::memcpy(epoch2, &epoch, sizeof(long));
    unsigned char number_pseudonyms2[sizeof(long)];
    std::memcpy(number_pseudonyms2, &number_pseudonyms, sizeof(long));
    unsigned char seed[uid_SIZE + 2 * sizeof(long)];
    std::memcpy(seed, uid, uid_SIZE);
    std::memcpy(seed + uid_SIZE, epoch2, sizeof(long));
    std::memcpy(seed + uid_SIZE + sizeof(long), number_pseudonyms2, sizeof(long));

    pseudonym2.epoch = this->epoch;

    crypto::generateKeys(seed, this->priv_key, pseudonym2.publicKey);

    crypto::pseudo_sign(epoch2, pseudonym2.sealedData, pseudonym2.publicKey, pseudonym2.Sig, spkp);

    this->pseudonym = pseudonym2;
  }

  void authenticate()
  {
    int numberFunctions;
    int treeDegree;
    int treeLevels;
    int piecesSize;
    long filterSize;
    unsigned char seed[32] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char rootSignature[64];
    unsigned char proof[crypto_sign_BYTES];

    // Specify the server address and port.
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(50051); // Server port
    // inet_pton(AF_INET, "146.193.41.248", &serverAddr.sin_addr); // Server IP address
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Server IP address

    auto start = std::chrono::high_resolution_clock::now();

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
      std::cerr << "Error: Socket creation failed\n";
      return;
    }
    sendRequestToAuthenticate(clientSocket, serverAddr);
    close(clientSocket);

    int sizeSecondMessage = 4;
    for (listDetails element : listOfFiltersDetails)
    {
      sizeSecondMessage += element.numberHashes * 8;
    }

    unsigned char secondMessage[sizeSecondMessage];
    int id = 2;
    memcpy(secondMessage, &id, sizeof(int));
    int offset = 4;
    int numberOfFilters = 0;

    std::vector<std::vector<int64_t>> allBits;

    nonRevocationProofs.reserve(listOfFiltersDetails.size());
    for (listDetails element : listOfFiltersDetails)
    {
      crypto::generateRevocationProof(element.seed, 32, this->priv_key, proof);
      std::vector<unsigned char> signatureVector(proof, proof + sizeof(proof));
      nonRevocationProofs.push_back(signatureVector);
      std::vector<int64_t> bits = clientBits(element.filterSize, element.numberHashes, proof);
      for (int64_t bit : bits)
      {
        memcpy(secondMessage + offset, &bit, sizeof(long));
        offset += 8;
      }
      numberOfFilters++;
      allBits.push_back(bits);
    }

    int clientSocket2 = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket2 == -1)
    {
      std::cerr << "Error: Socket creation failed\n";
      return;
    }
    bool revocationStatus = askForBits(clientSocket2, serverAddr, secondMessage, sizeSecondMessage, allBits);
    close(clientSocket2);

    if (revocationStatus)
    {
      int clientSocket3 = socket(AF_INET, SOCK_STREAM, 0);
      if (clientSocket3 == -1)
      {
        std::cerr << "Error: Socket creation failed\n";
        return;
      }
      bool authentication = sendPseudonym(clientSocket3, serverAddr);
      close(clientSocket3);

      if (authentication)
      {
        std::cout << "Authentication successful!" << std::endl;
      }
      else
      {
        std::cout << "Authentication did not succeded!" << std::endl;
      }
    }
    else
    {
      std::cout << "I'm revoked!" << std::endl;
    }

    listOfFiltersDetails.clear();
    nonRevocationProofs.clear();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::string filename = "durations_" + std::to_string(listOfFiltersDetails[0].filterSize) + "_" + std::to_string(listOfFiltersDetails[0].numberHashes) + "_" + std::to_string(listOfFiltersDetails[0].treeDegree) + "_" + std::to_string(listOfFiltersDetails[0].piecesSize) + ".txt";
    std::ofstream durationFile(filename, std::ofstream::app);
    durationFile << numberBytes << std::endl;
    durationFile.close();
    numberBytes = 0;
  }

  void sendRequestToAuthenticate(int clientSocket, struct sockaddr_in serverAddr)
  {
    int id = 1;
    unsigned char buffer[sizeof(int)];
    memcpy(buffer, &id, sizeof(int));
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      std::cerr << "Error: Connection failed\n";
      close(clientSocket);
      return;
    }

    ssize_t bytesSent = send(clientSocket, buffer, sizeof(int), 0);
    if (bytesSent == -1)
    {
      std::cerr << "Error: Failed to send numberFilter\n";
      close(clientSocket);
      return; // Indicate failure
    }

    char responseBuffer[8000];
    ssize_t bytesReceived = recv(clientSocket, responseBuffer, sizeof(responseBuffer) - 1, 0);
    if (bytesReceived <= 0)
    {
      std::cerr << "Error: Failed to receive response from server\n";
      close(clientSocket);
      return;
    }

    numberBytes += bytesReceived;

    int numberOfFilters;
    std::memcpy(&numberOfFilters, responseBuffer, 4);
    int offset = 4;

    for (int i = 0; i < numberOfFilters; i++)
    {
      struct listDetails lista;
      std::memcpy(&lista.seed, responseBuffer + offset, 32);
      offset += 32;
      std::memcpy(&lista.filterSize, responseBuffer + offset, 8);
      offset += 8;
      std::memcpy(&lista.numberHashes, responseBuffer + offset, 4);
      offset += 4;
      std::memcpy(&lista.treeDegree, responseBuffer + offset, 4);
      offset += 4;
      std::memcpy(&lista.piecesSize, responseBuffer + offset, 8);
      offset += 8;
      std::memcpy(&lista.treeLevels, responseBuffer + offset, 4);
      offset += 4;
      std::memcpy(&lista.pmsignature, responseBuffer + offset, 64);
      offset += 64;
      listOfFiltersDetails.push_back(lista);
    }
  }

  bool askForBits(int clientSocket, struct sockaddr_in serverAddr, unsigned char *buffer, int size, std::vector<std::vector<int64_t>> allBits)
  {
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      std::cerr << "Error: Connection failed\n";
      close(clientSocket);
      return false;
    }

    ssize_t bytesSent = send(clientSocket, buffer, size, 0);
    if (bytesSent == -1)
    {
      std::cerr << "Error: Failed to send numberFilter\n";
      close(clientSocket);
      return false; // Indicate failure
    }

    unsigned char sizeReceived[8];
    ssize_t bytesReceived = recv(clientSocket, sizeReceived, 8, 0);
    if (bytesReceived < 0)
    {
      std::cerr << "Error receiving data from server" << std::endl;
      return false;
    }

    long sizeOfMessage;
    std::memcpy(&sizeOfMessage, sizeReceived, sizeof(sizeOfMessage));

    std::vector<unsigned char> dataReceived(sizeOfMessage); // Resize the vector to hold the received data

    int totalReceived = 0;
    while (totalReceived < sizeOfMessage)
    {
      long bytesReceived = recv(clientSocket, dataReceived.data() + totalReceived, sizeOfMessage - totalReceived, 0);
      if (bytesReceived < 0)
      {
        std::cerr << "Error: Failed to receive vector data\n";
        close(clientSocket);
        return false;
      }
      totalReceived += bytesReceived;
    }

    numberBytes += bytesReceived + totalReceived;

    std::vector<std::vector<std::tuple<int, int, std::string>>> hashesReceived;
    std::vector<std::vector<std::tuple<int, std::string>>> piecesReceived;

    // Recover pieces and hashes from the information received

    long offset = 0;
    for (listDetails list : listOfFiltersDetails)
    {
      int piecesSize;
      if (list.piecesSize % 8 == 0)
      {
        piecesSize = list.piecesSize / 8;
      }
      else
      {
        piecesSize = (list.piecesSize / 8) + 1;
      }
      int numberPieces;
      std::memcpy(&numberPieces, dataReceived.data() + offset, sizeof(int));
      offset += sizeof(int);
      std::vector<std::tuple<int, std::string>> listaPiece;
      for (int e = 0; e < numberPieces; e++)
      {
        int numberOfPiece;
        std::memcpy(&numberOfPiece, dataReceived.data() + offset, sizeof(int));
        offset += sizeof(int);
        if (offset + piecesSize > dataReceived.size())
        {
          std::cerr << "Error: Not enough data to read the piece" << std::endl;
          return false; // Or handle the error as appropriate
        }
        std::string piece;
        piece.resize(piecesSize); // Resize the string to hold the piece
        // Copy piece data into the string
        std::memcpy(piece.data(), dataReceived.data() + offset, piecesSize);
        offset += piecesSize;
        // Ensure that the string is null-terminated if it represents a C-style string
        listaPiece.push_back({numberOfPiece, piece});
      }
      piecesReceived.push_back(listaPiece);
    }

    for (listDetails list : listOfFiltersDetails)
    {
      int numberPieces;
      std::memcpy(&numberPieces, dataReceived.data() + offset, sizeof(int));
      offset += sizeof(int);
      std::vector<std::tuple<int, int, std::string>> listaHash;
      for (int e = 0; e < numberPieces; e++)
      {
        int numberOfLayer;
        int numberOfHash;
        std::memcpy(&numberOfLayer, dataReceived.data() + offset, sizeof(int));
        offset += sizeof(int);
        std::memcpy(&numberOfHash, dataReceived.data() + offset, sizeof(int));
        offset += sizeof(int);
        std::string hash;
        hash.resize(32); // Resize the string to hold the hash
        std::memcpy(hash.data(), dataReceived.data() + offset, 32);
        offset += 32;
        listaHash.push_back({numberOfLayer, numberOfHash, hash});
      }
      hashesReceived.push_back(listaHash);
    }

    int count = 0;
    for (vector<int64_t> bits : allBits)
    {
      for (int bit : bits)
      {
        int piece = bit / (listOfFiltersDetails[count].piecesSize);
        int rest = bit % (listOfFiltersDetails[count].piecesSize);
        for (std::tuple<int, std::string> tuple : piecesReceived[count])
        {
          if (std::get<0>(tuple) == piece)
          {
            char byte = (std::get<1>(tuple))[rest / 8];
            if (!(byte & (1 << rest % 8)))
            {
              continue;
            }
            else
            {
              std::cout << "Authentication failed! I'm revoked!" << std::endl;
              return false;
            }
          }
        }
      }
      count++;
    }
    /*for (const auto& innerVec : piecesReceived) {
        for (const auto& tuple : innerVec) {
            std::cout << "(" << std::get<0>(tuple) << ", " << std::get<1>(tuple) << ") ";
        }
        std::cout << std::endl;
    }

    for (const auto& innerVec : hashesReceived) {
        for (const auto& tuple : innerVec) {
            std::cout << "(" << std::get<0>(tuple) << ", " << std::get<1>(tuple) << ", " << std::get<2>(tuple) << ") ";
        }
        std::cout << std::endl;
    }*/
    count = 0;
    for (std::vector<std::tuple<int, int, std::string>> hashes : hashesReceived)
    {
      std::string rootHash = merkleTree::verify(listOfFiltersDetails[count].treeLevels, listOfFiltersDetails[count].treeDegree, piecesReceived[count], hashes);
      if (!crypto::verifyRootSignature(rootHash, listOfFiltersDetails[count].seed, pk, listOfFiltersDetails[count].pmsignature))
      {
        std::cout << "Authentication failed! bad root signature" << std::endl;
        return false;
      }
      count++;
    }
    return true;
  }

  bool sendPseudonym(int clientSocket, struct sockaddr_in serverAddr)
  {
    auto start = std::chrono::high_resolution_clock::now();
    int countRevocationProofs = 0;
    for (vector<unsigned char> proof : nonRevocationProofs)
    {
      countRevocationProofs++;
    }

    int id = 3;
    unsigned char buffer[2 * sizeof(int) + 32 + 48 + crypto_aead_aes256gcm_ABYTES + 64 + countRevocationProofs * 64];
    int offset = 0;
    memcpy(buffer + offset, &id, sizeof(int));
    offset += 4;
    memcpy(buffer + offset, &this->epoch, sizeof(int));
    offset += 4;
    memcpy(buffer + offset, &this->pseudonym.publicKey, 32);
    offset += 32;
    memcpy(buffer + offset, &this->pseudonym.sealedData, 48 + crypto_aead_aes256gcm_ABYTES);
    offset += 48 + crypto_aead_aes256gcm_ABYTES;
    memcpy(buffer + offset, &this->pseudonym.Sig, 64);
    offset += 64;

    for (std::vector<unsigned char> proof : nonRevocationProofs)
    {
      memcpy(buffer + offset, proof.data(), 64);
      offset += 64;
    }

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
      std::cerr << "Error: Connection failed\n";
      close(clientSocket);
      return false;
    }

    ssize_t bytesSent = send(clientSocket, buffer, 2 * sizeof(int) + 32 + 48 + crypto_aead_aes256gcm_ABYTES + 64 + 64, 0);
    if (bytesSent == -1)
    {
      std::cerr << "Error: Failed to send numberFilter\n";
      close(clientSocket);
      return false; // Indicate failure
    }

    char responseBuffer[5];                                                                // Allocate buffer for response ("true" or "false" plus null terminator)
    ssize_t bytesReceived = recv(clientSocket, responseBuffer, sizeof(responseBuffer), 0); // Receive response
    if (bytesReceived <= 0)
    {
      std::cerr << "Error: Failed to receive response from server\n";
      close(clientSocket);
      return false; // Handle error
    }

    numberBytes += bytesReceived;

    responseBuffer[bytesReceived] = '\0'; // Null terminate the received data

    auto end = std::chrono::high_resolution_clock::now();

    if (strcmp(responseBuffer, "true") == 0)
    {
      return true;
    }
    else if (strcmp(responseBuffer, "false") == 0)
    {
      return false;
    }
    else
    {
      std::cerr << "Error: Invalid response from server\n";
      return false;
    }
  }

private:
  Pseudonym pseudonym;
  unsigned char priv_key[crypto_sign_ed25519_SECRETKEYBYTES];
  long epoch;
  long number_pseudonyms;
};

int main(int argc, char *argv[])
{
  Client client;
  crypto::generatePmKeys(pk, spkp);
  int numIterations = 2000;
  for (int i = 0; i < numIterations; i++)
  {
    client.admin_get_pseudonym();
    client.authenticate();
  }
  return 0;
}