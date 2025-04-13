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
#include "include/Pseudonym.h"
#include <chrono>
#include <fstream>

typedef struct {
    bool success;
    unsigned char nonRevocationProof[64];
} FirstMessageResult;

//PM keys
unsigned char spkp[crypto_sign_ed25519_SECRETKEYBYTES];
unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

class Client {
public:
  Client() 
    {
        epoch = 1;
        number_pseudonyms = 0;
    }

  FirstMessageResult askForBloomFilter(int clientSocket, struct sockaddr_in serverAddr, int numberFilter, unsigned char* priv_key){
    FirstMessageResult result;
    unsigned char buffer[sizeof(int)];
    memcpy(buffer, &numberFilter, sizeof(int));

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
      std::cerr << "Error: Connection failed\n";
      close(clientSocket);
      return result;
    }

    ssize_t bytesSent = send(clientSocket, buffer, sizeof(int), 0);
    if (bytesSent == -1) {
        std::cerr << "Error: Failed to send numberFilter\n";
        close(clientSocket);
        return result; // Indicate failure
    }

    // Receive the first data from the server
    unsigned char receivedData[2*sizeof(long) + sizeof(int) + 32 + 64];
    ssize_t bytesReceived = recv(clientSocket, receivedData, sizeof(receivedData), 0);
    if (bytesReceived == -1) {
        std::cerr << "Error: Failed to receive data from server\n";
        close(clientSocket);
        return result; // Indicate failure
    }

    //Separate Data.
    long vectorSize;
    memcpy(&vectorSize, receivedData, sizeof(long));
    long filterSize;
    memcpy(&filterSize, receivedData + sizeof(long), sizeof(long));
    int numberFunctions;
    memcpy(&numberFunctions, receivedData + 2 * sizeof(long), sizeof(int));
    unsigned char* seed = new unsigned char[32];
    memcpy(seed, receivedData + 2 * sizeof(long) + sizeof(int), 32);
    unsigned char* filterSignature = new unsigned char[64];
    memcpy(filterSignature, receivedData + 2 * sizeof(long) + sizeof(int) + 32, 64);

    std::vector<char> filter;
    filter.resize(vectorSize);

    int totalReceived = 0;
    while (totalReceived < vectorSize) {
      int bytesReceived = recv(clientSocket, filter.data() + totalReceived, vectorSize - totalReceived, 0);
      if (bytesReceived == -1) {
        std::cerr << "Error: Failed to receive vector data\n";
        close(clientSocket);
        return result;
      }
      totalReceived += bytesReceived;
    }

    bloomFilter filter2(filter, filterSize, numberFunctions); 

    unsigned char proof[crypto_sign_BYTES];
    crypto::generateRevocationProof(seed, 32, priv_key, proof);

    if (filter2.possiblyContains(proof, 64)){
      std::cout << "Non revocation proof esta no bloom filter" << std::endl;
      result.success = false;
      return result;
    }    
        
    if (!crypto::verifySignBloomFilter(filter, 0, seed, pk, filterSignature)){
      std::cout << "a assinatura esta mal feita" << std::endl;
      result.success = false;
      return result;   
    }

    result.success = true;
    std::copy(proof, proof + crypto_sign_BYTES, result.nonRevocationProof);
    return result;
  }

  bool sendPseudonym(int clientSocket, struct sockaddr_in serverAddr, unsigned char* proof){
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
      std::cerr << "Error: Connection failed\n";
      close(clientSocket);
      return false;
    }

    unsigned char dataToSend[sizeof(int) + 32 + 48 + crypto_aead_aes256gcm_ABYTES + 64 + 64];
    memcpy(dataToSend, &this->epoch, sizeof(int));
    memcpy(dataToSend + sizeof(int), &this->pseudonym.publicKey, 32);
    memcpy(dataToSend + sizeof(int) + 32, &this->pseudonym.sealedData, 48 + crypto_aead_aes256gcm_ABYTES);
    memcpy(dataToSend + sizeof(int) + 32 + 48 + crypto_aead_aes256gcm_ABYTES, &this->pseudonym.Sig, 64);
    memcpy(dataToSend + sizeof(int) + 32 + 48 + crypto_aead_aes256gcm_ABYTES + 64, proof, 64);
    
    ssize_t bytesSent = send(clientSocket, dataToSend, sizeof(int) + 32 + 48 + crypto_aead_aes256gcm_ABYTES + 64 + 64, 0);
    if (bytesSent == -1) {
        std::cerr << "Error: Failed to send numberFilter\n";
        close(clientSocket);
        return false; // Indicate failure
    }

    char responseBuffer[5]; // Allocate buffer for response ("true" or "false" plus null terminator)
    ssize_t bytesReceived = recv(clientSocket, responseBuffer, sizeof(responseBuffer) - 1, 0); // Receive response
    if (bytesReceived <= 0) {
        std::cerr << "Error: Failed to receive response from server\n";
        close(clientSocket);
        return false; // Handle error
    }

    responseBuffer[bytesReceived] = '\0'; // Null terminate the received data

    if (strcmp(responseBuffer, "true") == 0) {
        return true;
    } else if (strcmp(responseBuffer, "false") == 0) {
        return false;
    } else {
        std::cerr << "Error: Invalid response from server\n";
        return false;
    }
  }

  void admin_get_pseudonym(){ //this fuction should comunicate with the pseudonym manager, but for evaluation porpuses only we generate the pseudonum localy        
    unsigned char uid[32] = "KGtKgs+0W5/GODnJJS3JvV8MSLDS38A";
    this->number_pseudonyms = this->number_pseudonyms + 1;
    unsigned char sealedData2[64] = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK";
    Pseudonym pseudonym2;

    unsigned char epoch2[sizeof(int)];
    std::memcpy(epoch2, &epoch, sizeof(int));
    unsigned char number_pseudonyms2[sizeof(long)];
    std::memcpy(number_pseudonyms2, &number_pseudonyms, sizeof(long));
    unsigned char seed[uid_SIZE + sizeof(long) + sizeof(int)];
    std::memcpy(seed, uid, uid_SIZE);
    std::memcpy(seed + uid_SIZE, epoch2, sizeof(int));
    std::memcpy(seed + uid_SIZE + sizeof(int), number_pseudonyms2, sizeof(long));

    //crypto::aes_gcm_encrypt(pseudonym2.sealedData, seed, 48);
    pseudonym2.epoch = this->epoch;

    crypto::generateKeys(seed, this->priv_key, pseudonym2.publicKey);

    crypto::pseudo_sign(epoch2, pseudonym2.sealedData, pseudonym2.publicKey, pseudonym2.Sig, spkp);
        
    this->pseudonym = pseudonym2;
  }

  void authenticate (int numberOfFiltersToReceive){
    // Specify the server address and port
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(50051); // Server port
    //inet_pton(AF_INET, "146.193.41.248", &serverAddr.sin_addr); // Server IP address
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // Server IP address
    
    int numIterations = 50;  
    for (int e = 0; e < numIterations; e++){
      auto start = std::chrono::high_resolution_clock::now();
      for (int i = 1; i < numberOfFiltersToReceive+1; i++){
        // Create a socket
        int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1) {
            std::cerr << "Error: Socket creation failed\n";
            return;
        }
        FirstMessageResult x = askForBloomFilter(clientSocket, serverAddr, i, priv_key);
        close(clientSocket);
        
        int clientSocket2 = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket2 == -1) {
            std::cerr << "Error: Socket creation failed\n";
            return;
        }
        if (x.success && i == numberOfFiltersToReceive){
          if (sendPseudonym(clientSocket2, serverAddr, x.nonRevocationProof)){
            //std::cout << "Authentication successful!" << std::endl;
          }else{
            std::cout << "Server refused authentication!" << std::endl;
          }
        }
        else{
          //std::cout << "I'm revoked!" << std::endl;
        }      
        close(clientSocket2);
      }
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double> duration = end - start;
      std::cout << "A duracao da autenticao foi: " << duration.count() << " segundos" << std::endl;
      std::string filename = "durations.txt";
      std::ofstream durationFile(filename, std::ofstream::app);
      durationFile << duration.count() << std::endl;
      durationFile.close();
    }
  }

private:
  Pseudonym pseudonym;
  unsigned char priv_key[crypto_sign_ed25519_SECRETKEYBYTES];
  int epoch;
  long number_pseudonyms;
};

//./client numberOfFiltersToReceive
int main(int argc, char* argv[]) {
  int numberOfFiltersToReceive = std::stoi(argv[1]);
  Client client;
  crypto::generatePmKeys(pk, spkp);
  client.admin_get_pseudonym();
  client.authenticate(numberOfFiltersToReceive);
  return 0;
}
