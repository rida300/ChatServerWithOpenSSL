#include <time.h>
#include <string.h>
#include "inet.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <malloc.h>  /*FOR MEMORY ALLOCATION */
#include <arpa/inet.h>  /*for using ascii to network bit*/
#include <netinet/in.h>        /* network to asii bit */
#include <resolv.h>  /*server to find out the runner's IP address*/ 
#include "openssl/ssl.h" /*using openssl function's and certificates and configuring them*/
#include "openssl/err.h" /* helps in finding out openssl errors*/
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>



#define MAXTOPIC  100
#define MAXMSG 100

struct entity {
    int sockfd;
    char identity[7];
    char topic[MAXTOPIC];
    char port[5];
    char IP[15];
    struct entity * next;
    struct entity * prev;
};

char ** allTops;
SSL ** allSSLs;
int sslIndex=0;
char buffer[MAXMSG];
struct entity* headptr = NULL;
int nbytes;
char pt[MAXTOPIC+5];
char portG[5];
char topicG[MAXTOPIC];
char ipG[14];
char * allChats;
int shutDown;

/* 
adds a new server to the lined list by using the port and topic provided as arguments.
Also checks to find duplicates, if found, the server will exit on its side.
Creates a new server struct and copies the port, ip and topic into that struct.
Appends it to the end of the linked list
*/


/*
Sends the available chat rooms to the client.
Queries through the linked list, creates a string separated by commas to differentiate 
between the port, and topic.
An additional character is prefixed to the end of the string to let the client know that 
it has received all chat room. The character is 'd' if all are sent or 'g' if in progress
*/


/*
removes all cliients from the linked list that belong to the server that was shit down
readjusts links between cells
*/

void removeServer(SSL * ssl, char * topic)
{
    fprintf(stderr, "In remove server\n");
    fprintf(stderr, "the topic is: %s\n", topic);
	struct entity * curr = headptr;
    while (curr->next != NULL)
    {
        if(strcmp(curr->next->topic, topic) ==0)
		{
            fprintf(stderr, "found the topic, corresponding port is %s\n", curr->next->port);
			strncpy(curr->next->topic, "\0", sizeof(char)*MAXTOPIC);
            strncpy(curr->next->port, "\0", sizeof(char)*MAXTOPIC);
			if(curr->next->next != NULL)
			curr->next->next->prev = curr;
            else
            curr->next = NULL;
            
            break;
		}
        curr= curr->next;
    }
    return;
}


/*
checks to see if a 0 was received which shows the server quit*/
void checkEndMsg(SSL * ssl, char *m)
{
    fprintf(stderr, "in checkEndMsg\n");
    fprintf(stderr, "m is: %s\n", m);
    fprintf(stderr, "first char of m is: %c\n", m[0]);
    char *ps = malloc(sizeof(char)*100);
    strcpy(ps, m);
    fprintf(stderr, "ps is %s\n", ps);
    ps++;
    fprintf(stderr, "new ps is %s\n", ps);
    fprintf(stderr, "m is %s\n", ps);
	removeServer(ssl, ps);
}

/*creating and setting up ssl context structure*/
SSL_CTX* InitServerCTX()      
{  
    SSL_METHOD *method;
    SSL_CTX *ctx;       
    OpenSSL_add_all_algorithms();    /* load & register all cryptos, link the libraries. */
    SSL_load_error_strings();        /* load and link all error messages */
    method = TLSv1_2_server_method();   
    /* create new server-method instance. A TLS/SSL connection established with these
    methods will only understand the TLSv1.2 protocol.*/

    ctx = SSL_CTX_new(method);       /* create a new SSL_CTX from method 
    as framework to establish TLS/SSL or DTLS enabled connections */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)   /* to load a certificate into an SSL_CTX structure*/
{
    /* set the local certificate from CertFile
       loads the certificate x into ctx
       On success, the functions return 1. 
       Otherwise check out the error stack to find out the reason.
    */
    
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        fprintf(stderr, "In LoadCertificates\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* verify private key */
    fprintf(stderr, "check private key result is: %d\n", SSL_CTX_check_private_key(ctx));
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(1);
    }
    /*COME BACK*/
    /*VerifyCert(CertFile);*/
    return;
}

void ShowCerts(SSL* ssl)     /*show the ceritficates to client and match them*/
{  
    X509 *cert; /*certificate*/
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  
        printf("Server: %s\n", line);     /*server certifcates*/
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("client: %s\n", line);     /*client certificates*/
        free(line);
        X509_free(cert);
    }
    else
    printf("No certificates.\n");
    
}


/*adds client to the linked list, calls refuse)dups to ensure no duplicates. Asks the user to re-enter 
name if empty or duplicate*/
int addNewEntity(int sockfd, SSL * ssl)
{
    fprintf(stderr, "in addNewEntity\n");
    int e;
    int deDup;
    struct entity * newEntity = (struct entity *) malloc(sizeof(struct entity));
    char * entityIdentity= malloc(sizeof(char) * 7);
    struct entity * curr = headptr;
    struct entity * checkDupHead = headptr;
    if (headptr == NULL)
    {
        return -1;
    }
    while (curr->next != NULL)
    {
        curr = curr->next;
    }
    newEntity->sockfd = sockfd;
    newEntity->next = NULL;
    fprintf(stderr, "about to write from addClient\n");

    int readIdentity = SSL_read(ssl, entityIdentity, 7);
    fprintf(stderr, "read identity bytes= %d\n", readIdentity);
    if(entityIdentity[0] == ',')
    {
        checkEndMsg(ssl, entityIdentity);
    }
    fprintf(stderr, "the identity is %s\n", entityIdentity);
    if(strcmp(entityIdentity, "Server\0")==0)
    {
        char topicLocal[MAXTOPIC];
        strncpy(newEntity->identity, entityIdentity, sizeof(entityIdentity));
        fprintf(stderr, "about to read the topic is\n");
        SSL_read(ssl, topicLocal, sizeof(char)*MAXTOPIC);

        fprintf(stderr, "the topic is %s\n", topicLocal);
        
        while (checkDupHead->next != NULL)
        {
            fprintf(stderr, "entered the while\n");
            deDup = strcmp(checkDupHead->next->topic, topicLocal);
            if(deDup == 0)
            {
                
                fprintf(stderr, "found a dup\n");
                int bytesWritten = SSL_write(ssl, "A chatroom with this name already exists. Bye!", sizeof(char)*47);
                fprintf(stderr, "bytes written = %d\n", bytesWritten);
                break;
            }
            checkDupHead= checkDupHead->next;
            fprintf(stderr, "exiting while\n");

        }
        fprintf(stderr, "deDup is %d\n", deDup);
        if(deDup != 0 )
        {
            SSL_write(ssl, "continue", sizeof(char)*9);
            fprintf(stderr, "entered continued reading\n");
            strncpy(newEntity->topic, topicLocal, sizeof(char)*MAXTOPIC);
            SSL_read(ssl, newEntity->port, sizeof(char)*5);
            fprintf(stderr, "the port is %s\n", newEntity->port);
            SSL_read(ssl, newEntity->IP, sizeof(char)*14);
            fprintf(stderr, "the ip is %s\n", newEntity->IP);
        }
        fprintf(stderr, "exiting step no 1\n");
        curr->next = newEntity;
        fprintf(stderr, "exiting step no 2\n");
        fprintf(stderr, "sslIndex is %d\n", sslIndex);
        allSSLs[sslIndex] = ssl;
        fprintf(stderr, "exiting step o 3\n");
        sslIndex++;
        fprintf(stderr, "exiting step no 4\n");

        return 1; 
        /*returning 1 to not close the connection so that ssl connection is
         maintained to get interrupts for removing the server from the list*/
    }

    if(strcmp(entityIdentity, "Client\0")==0)
    {
        strncpy(newEntity->identity, entityIdentity, sizeof(entityIdentity));
        struct entity * list = headptr;
        int someSize = (sizeof(char)*(MAXTOPIC+3+5));
        char * element;
        /*only 1 chatroom*/
        if(list->next != NULL && list->next->next == NULL)
        {
            fprintf(stderr, "in single chatrroom if\n");
            element = malloc(sizeof(char)*someSize);
            strcpy(element, "d,");
            element = strcat(element, list->next->topic);
            element = strcat(element, ",");
            element = strcat(element, list->next->port);
            int sentChatRoom = SSL_write(ssl, element, someSize);
            fprintf(stderr, "element id: %s\n", element);
            fprintf(stderr, "bytes sent to client: %d\n", sentChatRoom);
            /*checkpoint*/
            /*free(element);*/
            /*memset(element, '\0', sizeof(element));*/
            fprintf(stderr, "exiting step 1\n");
        }
        else
        {
            fprintf(stderr, "in multiple chatrroom if\n");
            list=list->next;
            while (list != NULL )
            {
                fprintf(stderr, "in while\n");
                element = malloc(sizeof(char)*someSize);
                if(list->next == NULL)
                {
                    strcpy(element, "d,");
                }
                else
                {
                    strcpy(element, "g,");
                }
                element = strcat(element, list->topic);
                element = strcat(element, ",");
                element = strcat(element, list->port);
                int sentChatRoom = SSL_write(ssl, element, someSize);
                fprintf(stderr, "element id: %s\n", element);
                fprintf(stderr, "bytes sent to client: %d\n", sentChatRoom);
                memset(element, '\0', sizeof(element));
                list = list->next;
            }
        }
        fprintf(stderr, "exiting step before free\n");
        /*free(entityIdentity);*/
        fprintf(stderr, "exiting step 2\n");
        return 0; /*return 0 if it is the client and close the ssl connection*/
    }    
}

int main(int argc, char *argv)
{   
    SSL_CTX * ctx;
    int sockfd;
    allSSLs = malloc(sizeof(SSL *) * 10);
    struct sockaddr_in cli_addr, serv_addr;
    int serverLength;
    int serverCounter = 0;
    fd_set active_fd_set;
    fd_set read_fd_set;
    int messageLength = 0;
    struct entity * head = (struct entity *) malloc((sizeof(struct entity)));

    headptr = head;
    strncpy(head->topic, "\0", 1);
    strncpy(head->identity, "\0", 1);
    strncpy(head->port, "\0", 1);
    strncpy(head->IP, "\0", 1);
    head->prev = NULL;
    head->next = NULL;
    SSL_library_init();
    ctx = InitServerCTX();
    LoadCertificates(ctx, "directoryServer.pem", "directoryServer.pem");

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        
        perror("server: can't open stream socket");
        exit(1);
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    serv_addr.sin_port = htons(SERV_TCP_PORT);
    int fdMax;
    int listener;
    int newFd;
    
    /* Bind socket to local address */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("server: can't bind local address ds");
        return(1);
    }
    listen(sockfd, 10);
    
    
    printf("after the listen\n");
    serverLength = sizeof(serv_addr);
    int clilen= sizeof(cli_addr);
    SSL * ssl;
    for (; ; )
    {
        int pendingIndex;
        for(pendingIndex=0; pendingIndex< sslIndex; pendingIndex++)
        {
            int pending = SSL_pending(allSSLs[pendingIndex]);
            fprintf(stderr, "pending received %d\n", pending);
            if(pending >0 )
            {
                char * pend = malloc(sizeof(char)*100);
                int pendRead= SSL_read(allSSLs[pendingIndex], pend, sizeof(char)*100);
                checkEndMsg(allSSLs[pendingIndex], pend);
            }
        }
        char identity[7];
        int i;
        char * messageBuffer=  malloc(sizeof(char) * (MAXMSG*2));
        /* Service all the sockets with input pending. */
        int acceptedClient = accept(sockfd, &(cli_addr), (unsigned*)&clilen);
        if (acceptedClient < 0)
        {
            perror("Connection was not accepted");
            exit(1);
        }
        fprintf(stderr, "accepting a new client\n");
        
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, acceptedClient);
        int sslAccept = SSL_accept(ssl);
        fprintf(stderr, "sslAccept is %d\n", sslAccept);
        int addResult;
        if(sslAccept > 0)
        {
            fprintf(stderr, " ssl connection was successfull\n");
            addResult = addNewEntity(acceptedClient, ssl);
        }
        if(addResult == 0)
        {
        fprintf(stderr, "back in main\n");
        /*SSL_free(ssl);*/
        close(acceptedClient);
        }
        else
        {
            fprintf(stderr, "in else block to catch sig\n");
            char * quit =  malloc(sizeof(char)*100);
            int quitMsg = SSL_read(ssl, quit, sizeof(char)*100);
            fprintf(stderr, "quit bytes = %d\n", quitMsg);
            fprintf(stderr, "quit is %s\n", quit);
            if(quitMsg > 0 && quit[0] == ',')
            {
                fprintf(stderr, "in quit msg if block\n");
                checkEndMsg(ssl, quit);    
            }
        }
        fprintf(stderr, "add result is %d, should be ready to accept a new entity now\n", addResult);
        
    }               
}