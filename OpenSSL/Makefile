#
# Makefile for Example
#
LIBS	=
CFLAGS	= -g -ansi -pedantic

all:	tcp 

#
# Internet stream version (TCP protocol).
#

tcp:	chatServer2 chatClient2 directoryServer2
chatClient2.o chatServer2.o directoryServer2.o: inet.h

chatServer2:	chatServer2.o 
	#gcc -Wall -o server chatServer2.c -lssl -lcrypto
	gcc -Wall -o server chatServer2.c -lssl -lcrypto


#openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout certChatServer.pem -out certChatServer.pem
# openssl pkey -in certChatServer.pem to retrieve the private key of the certificate



chatClient2:	chatClient2.o 
	gcc -Wall -o client chatClient2.c -lssl -lcrypto

directoryServer2:	directoryServer2.o 
	gcc -Wall -o directoryServer directoryServer2.c -lssl -lcrypto

#
# Clean up the mess we made
#
clean:
	rm *.o \
	server4 client4
 
