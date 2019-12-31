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
#include <signal.h>
#include <malloc.h>  /*FOR MEMORY ALLOCATION */
#include <arpa/inet.h>  /*for using ascii to network bit*/
#include <netinet/in.h>        /* network to asii bit */
#include <resolv.h>  /*server to find out the runner's IP address*/ 
#include "openssl/ssl.h" /*using openssl function's and certificates and configuring them*/
#include "openssl/err.h" /* helps in finding out openssl errors*/
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define MAXCLIENTNAME 100
#define MAXMSG  100
#define MAXTOPIC 100

void sigintHandler();
int refuse_duplicates(char *);
void registerServer(char * , char *, char * );
void removeClients();

char * globalTopic;
char buffer[MAXMSG];
int nbytes;
int portSelected;
int sockFdDirectory;
struct sockaddr_in  cliu_addr, servu_addr;
int sigResult=0;

SSL_CTX *ctxR;
SSL *ssl;

int sockfds[10];
SSL ** allSSLs;
int sockCount = 0;
int sslCount = 0;

struct client {
    int sockfd;
    SSL *  sslClient;
    char name[MAXCLIENTNAME];
    struct client * next;
    struct client * prev;
};

struct client* headptr = NULL;


/*
broadcasts to all clients in the linked list
separate if and lese for msg and client addition*/
void broadcast(char * msg, int msgOrAddition)
{
    if (headptr == NULL || msg == NULL || strcmp(msg, "") == 0)
        return;
    struct client * currentNode = headptr;
    char name[MAXCLIENTNAME];
    char bufferb[MAXMSG+MAXCLIENTNAME+5];
    /* Broadcasting the message*/
    if (msgOrAddition != -1)
    {
        while (currentNode->next != NULL)
        {
            if(currentNode->next->sockfd == msgOrAddition)
            {
                strcpy(name, currentNode->next->name);
                break; /*found the client who sent the msg, no need to continue looping*/
            }
            currentNode = currentNode->next;
        }
    sprintf(bufferb, "%s: %s\n", name, msg);
    /*
    strcpy(bufferb, name);
    bufferb = strcat(bufferb, ": ");
    bufferb = strcat(bufferb, msg);
    */
   
    }
    else
    {

        /*Broadcasting the addition of a client
        char * msgJoined = " has joined the chat\n";
        char * concat = malloc(sizeof(char)*(22+MAXCLIENTNAME));
        concat= strcat(msg, msgJoined);
        strcpy(bufferb, concat);
        sprintf(bufferb, "%s\n", msg);
        */

        sprintf(bufferb, "%s\n", msg);
    /*  printf("%s\n", msg);
        fflush(stdout);*/

    }
    currentNode=headptr;
    int i;
    for(i = 0; i < sslCount; i++)
    {
        SSL_write(allSSLs[i], bufferb, sizeof(char)*(MAXMSG+MAXCLIENTNAME+4));
    }
    return;
}

/*adds client to the linked list, calls refuse)dups to ensure no duplicates. Asks the user to re-enter 
name if empty or duplicate*/
int addNewClient(SSL * ssl, int sockfd)
{
    if (headptr == NULL)
    {
        return -1;
    }

    int e;
    char clientName[MAXCLIENTNAME];
    struct client * currentNode = headptr;
    struct client * newClient = (struct client *) malloc(sizeof(struct client));
    
    while (currentNode->next != NULL)
    {
        currentNode = currentNode->next;
    }
    newClient->sockfd = sockfd;
    newClient->sslClient = ssl;
    newClient->next = NULL;
    char joiningMsg[MAXCLIENTNAME+30];
    char * initialMsg= "Please enter your name: ";
    int bytesWritten = SSL_write(ssl, initialMsg, strlen(initialMsg) );
    /*int err = SSL_get_error(ssl, bytesWritten);
    fprintf(stderr, "err code is %d\n", err);
    */

    int clientNameRead = SSL_read(ssl, clientName, sizeof(char)*MAXCLIENTNAME);

    while ((e = refuse_duplicates(clientName)) != 0|| strcmp(clientName, "")==0)
    {
        memset(clientName, '\0', sizeof(clientName));
        char * takenName = "This name is taken. Choose another one: ";
        int takenBytesSent = SSL_write(ssl, takenName, strlen(takenName));
        int clientNameRead2 = SSL_read(ssl, clientName, sizeof(char)*MAXCLIENTNAME);
    }

    strcpy(newClient->name, clientName);
    currentNode->next = newClient;

    if (strlen(currentNode->name) == 0)
    {
        strcpy(joiningMsg, "You are the first user to join the chat.");
    }
    else
    {
        char * temp = " has joined the chat!";
        char * concat = strcat(clientName, temp);
        strcpy(joiningMsg, concat);
    }
    /*calls broadcast to announce addition of client
    Last argument for broadcast indicates if broadcasting addition or msg
    Last arg = 1 means new client
    Last arg = 0 means new msg
    */
    sockfds[sockCount] = sockfd;
    sockCount++;
    allSSLs[sslCount] = ssl;
    sslCount++;
    broadcast(joiningMsg, -1);
    return 1;
}


/*queries linked list to see if new client's name is already present*/
/*returns 1 if given name is empty, -1 if duplicate found*/
int refuse_duplicates(char * name)
{
    struct client * currentNode = headptr;
    if (headptr == NULL)
    {
        exit(-1);
    }
    if (strcmp(name, "") == 0 || strcmp(name, "\0") == 0 || strcmp(name, " ") == 0 || name == NULL) {
     
        return 1;
    }

    while (currentNode->next != NULL)
    {
        /*name[strlen(name)-1] = 0;*/
        if (strcmp(currentNode->next->name, name) == 0 || strcmp(name, "")==0)
        {
            return -1;
        }
        currentNode = currentNode->next;
    }
    return (0);
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

SSL_CTX* InitCTX(void)     /*creating and setting up ssl context structure*/
{   
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
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
    fprintf(stderr, "calling verifyCert\n");
    /*COME BACK*/
    /*VerifyCert(CertFile);*/
    return;
}

void VerifyDirectoryCert(SSL * ssl, char * topic)
{
    fprintf(stderr, "in verifyCertTopic\n");
    X509 *cert;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        fprintf(stderr, "cert was not null\n");
        char * commonName = malloc(sizeof(char)*100);
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, commonName,sizeof(char)*100);
        fprintf(stderr, "common name is %s\n", commonName);
        fprintf(stderr, "topic name is %s\n", topic);
        fprintf(stderr, "strcmp returned %d\n", strcmp(commonName, topic));
        if(strcmp(commonName, topic) !=0 ) /*hard coded for now*/
        {
          fprintf(stderr, "Topic and certificate mismatched. Goodbye!\n");
          exit(0);
        }
    }
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

/*to re register server, sigint handler is used, it sends the indication to 
directory server to remove it from the list of available chat room*/
void sigintHandler()
{   
    char * append = malloc(sizeof(char)*100);
	fprintf(stderr,"Goodbye! \n");
	/*removeClients();*/
    sprintf(append, ",%s", globalTopic);
    int writtenQuit = SSL_write(ssl, append, strlen(append));
    sigResult = 2;
    SSL_free(ssl);
    close(sockFdDirectory);
    SSL_CTX_free(ctxR);
    exit(0);
}

int main(int argc, char * argv[4])
{
    fd_set active_fd_set;
    fd_set read_fd_set;

    int sockfd;
    struct sockaddr_in  cli_addr, serv_addr;
    int clientLength;
    
    allSSLs = malloc(sizeof(SSL *) * 10);

    int selectedCount;
    int addResult;
    int i;
    int bytes_read;
    

    struct client * head = (struct client *) malloc((sizeof(struct client)));
    strncpy(head->name, "\0", 1);
    head->prev = NULL;
    head->next = NULL;
    headptr = head;
    char * messageBuffer=  malloc(sizeof(char) * (MAXMSG+5+MAXCLIENTNAME));
    int messageLength;

    struct timeval timeout;
    timeout.tv_sec=12000;
    timeout.tv_usec=0;/*microsec*/

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    OpenSSL_add_all_digests();
    if(argc!= 3)
    {
        fprintf(stderr, "Please provide the topic and port number\n");
        exit(1);
    }
    globalTopic = malloc(sizeof(char)*100);
    strcpy(globalTopic, argv[1]);
    /*signal(SIGTSTP, &sigintHandler);*/
    signal(SIGINT, &sigintHandler);
    registerServer(argv[1], argv[2], "129.130.10.43");
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */

    char * certiName = strcat(argv[1], ".pem");  /*COME BACK HERE*/
    LoadCertificates(ctx, certiName, certiName); /* load certs */ 
    /*COME BACK HERE*/
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        return(1);
    }

    /* Bind socket to local address */
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(portSelected); /*port from cml arg*/
    
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("server: can't bind local address");
        return(1);
    }
    FD_ZERO(&active_fd_set);
    FD_SET(sockfd, &active_fd_set);
    listen(sockfd, 10);

    SSL *ssl;
    sockfds[sockCount] = sockfd;
    sockCount++;
    clientLength = sizeof(cli_addr);
    for (; ; )
    {
        read_fd_set = active_fd_set;
        selectedCount = select(FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout);
        if (selectedCount <= 0)
        {
            perror("select");
            exit(1);
        }
        /* Service all the sockets with input pending. */
        for (i = 0; i < sockCount && selectedCount>0; ++i)
        {
            if (FD_ISSET(sockfds[i], &read_fd_set))
            {
                selectedCount--;
                 /* Accept a new client */
                if (sockfds[i] == sockfd)
                {
                    int acceptedClient;
                    acceptedClient = accept(sockfd, &(cli_addr), (unsigned*)&clientLength);
                    if (acceptedClient < 0)
                    {
                        perror("Connection was not accepted");
                        exit(1);
                    }
                    printf("Connection: %s:%d\n",inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));  /*printing connected client information*/
    
                    ssl = SSL_new(ctx);              /* get new SSL state with context */                
                    SSL_set_fd(ssl, acceptedClient);      /* set connection socket to SSL state */
                    /*VerifyCertTopic(ssl);*/ /*come back here*/
                    int sslAccept = SSL_accept(ssl);
                    
                    if ( sslAccept <= 0 )
                    {     
                        fprintf(stderr, "ssl_accept was not successful\n");
                        /* do SSL-protocol accept */
                        ERR_print_errors_fp(stderr);
                    }
                    
                    else
                    { 
                        ShowCerts(ssl);        /* get any certificates */
                        
                        addNewClient(ssl, acceptedClient);
                        FD_SET(acceptedClient, &active_fd_set);
                            
                    }
                }

                /* receive a message from an existing client */

                else 
                {                  
                    memset(messageBuffer, '\0', sizeof(messageBuffer)); /*revisit*/
                    messageLength = SSL_read(allSSLs[i-1], messageBuffer, MAXMSG); /*revisit*/
                    if(messageLength >= 0 && messageBuffer[0] != '\0')
                    {
                        printf("%s\n", messageBuffer);
                        broadcast(messageBuffer, sockfds[i]);
                        free(messageBuffer);
                    }

                }
            }    
        }
    }
    free(allSSLs);
    free(certiName);
}

/*remove all clients if the sigint was caught, also close the clients*/
void removeClients()
{
    int i;
    for(i = 0; i < sslCount; i++)
    {
        int quittingClients = SSL_write(allSSLs[i], "End", sizeof(char)*3);
        fprintf(stderr, "quittingClient written %d\n", quittingClients);
    }
}

/*registers the server with the directory server using UDP links*/
void registerServer(char * topic, char * port, char * ip)
{
    fprintf(stderr, "in register\n");
   
    SSL_library_init();
    ctxR = InitCTX();        /* initialize SSL */

    struct timeval read_timeout;
    int sentTopic;
    int recvDup;
    int servlen;
    int sockfdR;
    char               s[MAXMSG];
    int sentPort;
    char duped[43];
    char req;
    int sendPreShut;
    int connectResult;
    int i;
    int socketCount;
    portSelected = atoi(port);
    
    /*struct sockaddr_in  cliu_addr, servu_addr;*/

    memset((char *) &servu_addr, 0, sizeof(servu_addr));
    servu_addr.sin_family      = AF_INET;
    servu_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    servu_addr.sin_port        = htons(SERV_TCP_PORT);

    char sending [MAXTOPIC+5];
    /*popen hostnet -1*/
    if ((sockfdR =  socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket directory server");
        exit(1);
    }
    /* Connect to the server. */
    connectResult = connect(sockfdR, (struct sockfd *) &servu_addr,sizeof(servu_addr));
    if (connectResult < 0)
    {
        perror("Client did not connect to server");
        return(1);
    }
    ssl = SSL_new(ctxR);
    SSL_set_fd(ssl, sockfdR);
    int registerSSLConnect = SSL_connect(ssl);
    int err = SSL_get_error(ssl, registerSSLConnect);
    fprintf(stderr, "err code is %d\n", err);
    
    /* connection was successfully established by this point*/
    VerifyDirectoryCert(ssl, "directoryServer");
    
    ShowCerts(ssl);

    memset(s, 0, MAXMSG); /*reset s*/
    char * dupedT = malloc(sizeof(char) * 47);
    int identityWritten = SSL_write(ssl, "Server", 7);
    SSL_write(ssl, topic, sizeof(char)*MAXTOPIC);

    int bytesRead = SSL_read(ssl, dupedT, sizeof(char)*47);
   
    if(strcmp(dupedT, "A chatroom with this name already exists. Bye!") ==0)
    {
        fprintf(stderr, dupedT);
        exit(1);
    }
    SSL_write(ssl, port, sizeof(char)*5);

    SSL_write(ssl, ip, sizeof(char)*14);
    if(sigResult != 2)
    {
        SSL_write(ssl, "moveOn", sizeof(char)*7);
    }
    sockFdDirectory=sockfdR;
    
    free(dupedT);
    return;
}

