#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "openssl.h"

#define RSA_BITS 1024
#define RSA_PADDING RSA_PKCS1_PADDING

// Prints last occured error
void printLastError(char *msg)
{
    char *err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("\n%s ERROR: %s", msg, err);
    free(err);
}

// Generates RSA key pair
void createRsaPair(char *privateKey, char *publicKey)
{
    int keyLength, length;
    char *privateKeyTemp, *publicKeyTemp;
    RSA *rsa = RSA_generate_key(RSA_BITS, RSA_F4, 0, 0);
    BIO *bio;

    // Creating private key
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    keyLength = BIO_pending(bio);
    privateKeyTemp = calloc(keyLength + 1, 1);
    BIO_read(bio, privateKeyTemp, keyLength);
    BIO_free(bio);

    length = (int)(strlen(privateKeyTemp));

    for (int i = 0; i < length; i++)
        privateKey[i] = privateKeyTemp[i];

    // Creating public key
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);

    keyLength = BIO_pending(bio);
    publicKeyTemp = calloc(keyLength + 1, 1);
    BIO_read(bio, publicKeyTemp, keyLength);
    BIO_free(bio);

    length = (int)(strlen(publicKeyTemp));

    for (int i = 0; i < length; i++)
        publicKey[i] = publicKeyTemp[i];
}

// Creating RSA object
// key : public or private key
// isPublic : 1 for public and 0 for private
RSA *createRsa(unsigned char *key, int isPublic)
{
    RSA *rsa = NULL;
    BIO *bio;

    bio = BIO_new_mem_buf(key, -1);
    if (bio == NULL)
    {
        printf("\nFailed in creating key BIO");
        return 0;
    }

    if (isPublic)
        rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);

    else
        rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);

    if (rsa == NULL)
        printf("\nFailed in creatingf RSA object");

    BIO_free(bio);
    return rsa;
}

// Returns size of RSA object
// key : public or private key
// isPublic : 1 for public and 0 for private
int rsaSizeFrom(unsigned char *key, int isPublic)
{
    RSA *rsa = createRsa(key, isPublic);
    int size = RSA_size(rsa);
    RSA_free(rsa);
    return size;
}

// Encryption using public key
// source : data to be encrypted
// length : size of data to be encrypted
// destination : encrypted data
int encryptByPublicKey(unsigned char *source, int length, unsigned char *publicKey, unsigned char *destination)
{
    RSA *rsa = createRsa(publicKey, 1);
    return RSA_public_encrypt(length, source, destination, rsa, RSA_PADDING);
}

// Decryption using private key
// source : encrypted data
// length : size of encrpted data
// destination : decrypted data
int decryptByPrivateKey(unsigned char *source, int length, unsigned char *privateKey, unsigned char *destination)
{
    RSA *rsa = createRsa(privateKey, 0);
    return RSA_private_decrypt(length, source, destination, rsa, RSA_PADDING);
}