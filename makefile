all:
	gcc client.c openssl.c -o client -lssl -lcrypto -O3
	gcc server.c openssl.c -o server -lssl -lcrypto -O3
clean:
	rm -f *~ *.o 