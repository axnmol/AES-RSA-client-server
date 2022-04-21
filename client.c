/*
SE408:INS Final Project
Group Number - 11
Full code repository: https://github.com/axnmol/AES-RSA-client-server
*/

#include "openssl.h"

int main()
{
    int connectionSocket;
    struct sockaddr_in server;
    char message[BUFFER_LENGTH], serverReply[BUFFER_LENGTH];

    // Creating connection socket
    connectionSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (connectionSocket == -1)
    {
        printf("\nSocket not created");
        return 1;
    }
    printf("\nSocket created");

    // Connecting to remote server
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);
    if (connect(connectionSocket, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("\nConnection failed. Error");
        return 1;
    }
    printf("\nConnected to remote server\n");

    // Receiving server's public key
    printf("\nReceiving server's public key ...");
    memset(serverReply, 0, BUFFER_LENGTH);
    if (recv(connectionSocket, serverReply, BUFFER_LENGTH, 0) < 0)
    {
        printf("\nReceiving public key failed");
        return 1;
    }
    printf("\nReceived server's public key\n");
    printf("\nServer's public key is : \n%s", serverReply);
    fflush(stdout);

    // Generating an AES_KEY for symmetric encryption
    AES_KEY encryptionKey;
    unsigned char sessionKey[AES_KEY_LENGTH];
    if (!RAND_bytes(sessionKey, AES_KEY_LENGTH))
        exit(-1);
    AES_set_encrypt_key(sessionKey, AES_BITS, &encryptionKey);

    // Encrypting it with server's public key
    int encryptedLength = rsaSizeFrom(serverReply, 1);
    unsigned char *encryptedSessionKey =
        (unsigned char *)malloc(encryptedLength * sizeof(char));
    memset(encryptedSessionKey, 0, encryptedLength);

    int encryptedKeyLength = encryptByPublicKey(sessionKey, (int)(strlen(sessionKey)), serverReply, encryptedSessionKey);
    if (encryptedKeyLength == -1)
        printLastError("\nEncryption by public key failed ");

    // Sending encryption key to server
    if (send(connectionSocket, encryptedSessionKey, encryptedLength, 0) < 0)
    {
        printf("\nSending encryption key to server failed");
        return 1;
    }

    // Keep communicating with the remote server
    while (1)
    {
        memset(message, 0, sizeof(message));
        printf("\n-----------------------------------------------");
        printf("\nEnter message : ");
        fflush(stdin);

        if (scanf("%s", message) == 0)
        {
            printf("\nFailed to read the message");
            return 1;
        }

        unsigned char encryptedMessage[BUFFER_LENGTH];
        AES_encrypt(message, encryptedMessage, &encryptionKey);
        printf("Encrypted message is : %s", encryptedMessage);
        fflush(stdout);

        // Sending data
        if (send(connectionSocket, encryptedMessage, BUFFER_LENGTH, 0) < 0)
        {
            printf("\nSending message failed");
            return 1;
        }

        // Receiving a reply from the server
        memset(serverReply, 0, sizeof(serverReply));
        if (recv(connectionSocket, serverReply, BUFFER_LENGTH, 0) < 0)
        {
            printf("\nRecieving reply from the server failed");
            break;
        }
        printf("\nServer reply : %s", serverReply);
    }

    close(connectionSocket);
    return 0;
}