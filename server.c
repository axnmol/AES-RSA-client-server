/*
SE408:INS Final Project
Group Number - 11
Full code repository: https://github.com/axnmol/AES-RSA-client-server
*/

#include "openssl.h"

int main()
{
    int serverSocket, clientSocket, addrLength, readSize;
    struct sockaddr_in server, client;
    char clientMessage[BUFFER_LENGTH];

    // Creating server socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        printf("\nSocket not created");
        return 1;
    }
    printf("\nSocket created");

    // Binding to client
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8888);
    if (bind(serverSocket, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("\nBinding failed. Error");
        return 1;
    }
    printf("\nBinding done\n");

    // Listening
    listen(serverSocket, 3);

    // Generating RSA key pair
    char rsaPrivateKey[RSA_LENGTH], rsaPublicKey[RSA_LENGTH];
    memset(rsaPrivateKey, 0, RSA_LENGTH);
    memset(rsaPublicKey, 0, RSA_LENGTH);
    createRsaPair(rsaPrivateKey, rsaPublicKey);
    printf("\nServer's public key is : \n%s", rsaPublicKey);

    // Accepting incoming connection
    while (1)
    {
        printf("\nWaiting for incoming connections ...");
        addrLength = sizeof(struct sockaddr_in);

        // Accepting incoming connection from a client
        clientSocket = accept(serverSocket, (struct sockaddr *)&client, (socklen_t *)&addrLength);
        if (clientSocket < 0)
        {
            perror("\nAccepting connection failed");
            return 1;
        }
        printf("\nAccepted connection");

        // Sending server's public key to the client
        memset(clientMessage, 0, BUFFER_LENGTH);
        if (send(clientSocket, rsaPublicKey, BUFFER_LENGTH, 0) < 0)
        {
            printf("\nSending public key failed");
            return 1;
        }
        printf("\nServer's public key is sent to client\n");

        int encryptedLength = rsaSizeFrom(rsaPublicKey, 1);
        unsigned char *encryptedSessionKey = (unsigned char *)malloc(encryptedLength * sizeof(char));
        memset(encryptedSessionKey, 0, encryptedLength);
        unsigned char sessionKey[AES_KEY_LENGTH];
        memset(sessionKey, 0, AES_KEY_LENGTH);

        // Receiving AES session key from client
        memset(clientMessage, 0, BUFFER_LENGTH);
        if ((recv(clientSocket, clientMessage, BUFFER_LENGTH, 0)) <= 0)
        {
            printf("\nReceiving encryption key failed!");
            return 1;
        }
        memcpy(encryptedSessionKey, clientMessage, encryptedLength);
        fflush(stdout);

        // Decrypting AES session key
        int decryptedLength = decryptByPrivateKey(encryptedSessionKey, encryptedLength, rsaPrivateKey, sessionKey);
        if (decryptedLength == -1)
        {
            printLastError("\nDecrypting AES key failed");
            return 1;
        }
        fflush(stdout);

        // Setting the decryption key
        AES_KEY deccryptionKey;
        AES_set_decrypt_key(sessionKey, AES_BITS, &deccryptionKey);

        // Communication is established and data is received from the client
        memset(clientMessage, 0, BUFFER_LENGTH);
        while ((readSize = recv(clientSocket, clientMessage, BUFFER_LENGTH, 0)) > 0)
        {
            fflush(stdout);
            printf("\n-----------------------------------------------");
            printf("\nNew message received from the client\nEncrypted message is : %s", clientMessage);
            fflush(stdout);

            unsigned char decryptedMessage[BUFFER_LENGTH];
            AES_decrypt(clientMessage, decryptedMessage, &deccryptionKey);

            fflush(stdout);
            printf("\nDecrypted message is : %s", decryptedMessage);
            fflush(stdout);

            char serverMessage[BUFFER_LENGTH] = "Message received acknowledgement";
            send(clientSocket, serverMessage, BUFFER_LENGTH, 0);
            memset(clientMessage, 0, BUFFER_LENGTH);
        }

        if (readSize == 0)
        {
            printf("\nClient connection disconnected");
            fflush(stdout);
        }
        else if (readSize == -1)
            perror("\nReceiving message failed");
    }
}