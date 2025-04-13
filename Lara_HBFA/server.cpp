#include <string>
#include <cstdint> 
#include <iostream>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include "include/bloomFilter.h"
#include "include/crypto.h"

std::vector<bloomFilter> filters;
int numberFilters; 
unsigned char seed[32]; 
std::vector<std::vector<unsigned char>> signatures;
std::vector<std::stringstream> bitStreams;

//PM keys
unsigned char spkp[crypto_sign_ed25519_SECRETKEYBYTES];
unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

void sendFilterReply(int clientSocket, unsigned char* message){
  int receivedInteger;
  memcpy(&receivedInteger, message, sizeof(int));

  unsigned char dataToSend[2 * sizeof(long) + sizeof(int) + 32 + 64];
  memcpy(dataToSend, &filters[receivedInteger-1].numBytes, sizeof(long));
  memcpy(dataToSend + sizeof(long), &filters[receivedInteger-1].size, sizeof(long));
  memcpy(dataToSend + 2 * sizeof(long), &filters[receivedInteger-1].m_numHashes, sizeof(int));
  memcpy(dataToSend + 2 * sizeof(long) + sizeof(int), seed, 32);
  memcpy(dataToSend + 2 * sizeof(long) + sizeof(int) + 32, signatures[receivedInteger-1].data(), 64);

  // Send the joined data to the client
  ssize_t bytesSent = send(clientSocket, dataToSend, sizeof(dataToSend), 0);
  if (bytesSent == -1) {
      std::cerr << "Error: Failed to send joined data\n";
  }

  // Transfer the vector data
  if (send(clientSocket, filters[receivedInteger-1].bitArray.data(), filters[receivedInteger-1].bitArray.size() * sizeof(char), 0) == -1) {
      std::cerr << "Error: Failed to send vector data\n";
      close(clientSocket);
      return;
  }
}

void sendPseudonymReply(int clientSocket, unsigned char* message){
  unsigned char epoch2[sizeof(int)];
  unsigned char publicKey[32];
  unsigned char ciphertext[48 + crypto_aead_aes256gcm_ABYTES];
  unsigned char PMsignature[64];
  unsigned char NonRevocationProof[64];

  // Assuming the message structure is: epoch2 (int) + publicKey (32 bytes) + ciphertext + PMsignature + NonRevocationProof
  int offset = 0;
  memcpy(epoch2, message, sizeof(int));
  offset += sizeof(int);
  memcpy(publicKey, message + offset, sizeof(publicKey));
  offset += sizeof(publicKey);
  memcpy(ciphertext, message + offset, sizeof(ciphertext));
  offset += sizeof(ciphertext);
  memcpy(PMsignature, message + offset, sizeof(PMsignature));
  offset += sizeof(PMsignature);
  memcpy(NonRevocationProof, message + offset, sizeof(NonRevocationProof));

  //Verificar que o pseudonimo foi feito pelo PM
  bool pseudonymOk = crypto::verify_pseudo_sign(epoch2, ciphertext, publicKey, PMsignature, pk); 

  //verificar que a prova de nao estao no filtro bloom
  bool isInFilter = filters[numberFilters-1].possiblyContains(NonRevocationProof, 64);
    
  //Verificar que a prova de nao revogacao esta bem construida
  bool isOk = crypto::verifyProof(NonRevocationProof, seed, 32, publicKey);

  //std::cout << "o pseudonimo está ok ? = " << pseudonymOk << std::endl;
  //std::cout << "esta no filtro bloom ? = " << isInFilter << std::endl;
  //std::cout << "is well constructed ? = " << isOk << std::endl;

  if (isOk && !isInFilter && pseudonymOk) {
    // If verification is successful, send "true" to the client
    send(clientSocket, "true", strlen("true"), 0);
  } else {
    // If verification fails, send "false" to the client
    send(clientSocket, "false", strlen("false"), 0);
  }
}

class server{
  public:
  server(){
  }
  
  void createBloomFilters(long *initialSize, long *lastSize, float *factor, int *numHashes){
    unsigned char example[10]  ="123456789";  
    int count = 0;
    for(long i = *initialSize; i <= *lastSize; i*=*factor){
      bloomFilter filter(i, *numHashes); 
      filters.push_back(filter);
      count++;
    }
    numberFilters = count;
    std::cout << "numero de filtros : " << numberFilters << std::endl;
  }

  void signBloomFilters() {
    signatures.reserve(filters.size()); 
    int count = 0;
    for (bloomFilter& filter : filters){
      unsigned char signature[64];
      crypto::signBloomFilter(filters[count].bitArray, 0, seed, spkp, signature);
      std::vector<unsigned char> signatureVector(signature, signature + sizeof(signature));
      signatures.push_back(signatureVector);
      count++;
    }
  }
  
  void RunServer(){
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Socket creation failed\n";
        return;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP address
    serverAddr.sin_port = htons(50051); // Use port 50051
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error: Bind failed\n";
        close(serverSocket);
        return;
    }

    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Error: Listen failed\n";
        close(serverSocket);
        return;
    }

    while (true) {
      // Accept a client connection
      struct sockaddr_in clientAddr;
      socklen_t clientAddrLen = sizeof(clientAddr);
      int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
      if (clientSocket == -1) {
          std::cerr << "Error: Accept failed\n";
          close(serverSocket);
          return;
      }

      //std::cout << "Connection established with client\n";

      // Receive a message from the client
      unsigned char message[256];
      ssize_t bytesReceived = recv(clientSocket, message, sizeof(message), 0);
      if (bytesReceived <= 0) {
          std::cerr << "Error: Failed to receive message from client\n";
          close(clientSocket);
          continue; // Continue to accept next connection
      }
    
      if (bytesReceived == 4) {
        sendFilterReply(clientSocket, message);
      } else {
        sendPseudonymReply(clientSocket, message);
      }
      //printf("fechou o socket \n");
      close(clientSocket);
  }
  close(serverSocket);
  }
};

// ./server initialSize lastSize factor numberHashFunctions 
int main(int argc, char** argv) {
  long initialSize = std::stol(argv[1]);
  long lastSize = std::stol(argv[2]);
  char* end;
  float factor = std::strtof(argv[3], &end);
  int numberHashFunctions = std::stoi(argv[4]);

  crypto::generatePmKeys(pk, spkp);
  crypto::generateRandomSeed(seed);

  server myServer; 

  myServer.createBloomFilters(&initialSize, &lastSize, &factor, &numberHashFunctions);
  myServer.signBloomFilters();

  myServer.RunServer();
  return 0;
}