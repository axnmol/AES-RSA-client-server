#ifndef OPENSSL_H
#define OPENSSL_H

// Common include directives for client and server
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

// Common define directives used by client and server
#define AES_BITS 128
#define AES_KEY_LENGTH AES_BITS / 8
#define RSA_LENGTH 1000
#define BUFFER_LENGTH 1000

// Prints last occured error
void printLastError(char *msg);

// Generates RSA key pair
void createRsaPair(char *privateKey, char *publicKey);

// Returns size of RSA object
int rsaSizeFrom(unsigned char *key, int isPublic);

// Encryption using public key
int encryptByPublicKey(unsigned char *source, int length, unsigned char *publicKey, unsigned char *destination);

// Decryption using private key
int decryptByPrivateKey(unsigned char *source, int length, unsigned char *privateKey, unsigned char *destination);

#endif