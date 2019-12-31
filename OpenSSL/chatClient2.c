#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include "inet.h"
#include <malloc.h> /*FOR MEMORY ALLOCATION */
#include <resolv.h> /*server to find out the runner's IP address*/ 
#include <openssl/ssl.h> /*using openssl function's and certificates and configuring them*/
#include <openssl/err.h> /* helps in finding out openssl errors*/
#include <unistd.h>  /*FOR USING FORK for at a time send and receive messages*/ 

#define FAIL    -1 /*for error output == -1 */
#define MAX   100

char * portC;
char **chatRoomTopics;
char ** chatRoomPorts;
int globalIndex;

void registerWithDirectory();
int EndMessageCheck(char *);
void ShowCerts(SSL*);

SSL_CTX* InitCTX(void)     /*creating and setting up ssl context structure*/
{   
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method =    TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

void VerifyCertTopic(SSL * ssl, char * topic)
{
    X509 *cert;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        char * commonName = malloc(sizeof(char)*100);
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), 13, commonName,sizeof(char)*100);
       
        if(strcmp(commonName, topic) !=0 ) /*hard coded for now*/
        {
          fprintf(stderr, "Topic and certificate mismatched. Goodbye!\n");
          exit(0);
        }

       
    }
}

void ShowCerts(SSL* ssl)  /*show the ceritficates to server and match them but here we are not using any client certificate*/
{   
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
else
    printf("Info: No client certificates configured.\n");
}


void main(int argc, char ** argv )
{

    SSL_CTX *ctx;
    SSL *ssl;
    fd_set             active_fd_set;
    fd_set             read_fd_set;

    /*SSL_library_init();*/   /*load encryption and hash algo's in ssl*/
    registerWithDirectory();
    int hop;
    char * chosenTopic = malloc(sizeof(char)*MAX);
    for(hop =0; hop<globalIndex; hop++)
    {
        if(strcmp(chatRoomPorts[hop], portC)==0)
        {
            strcpy(chosenTopic, chatRoomTopics[hop]);
            break;
        }
    }

    int portInt = atoi(portC);
    int                sockfd;
    struct sockaddr_in serv_addr;
    char               s[MAX];
    int                response;
    int client_inputFD = fileno(stdin);
    int                i;
    int connectResult;
    int len;
    int socketCount;
    struct timeval timeout;
    timeout.tv_sec=1200000;
    timeout.tv_usec=0;/*microsec*/
    char clientName[MAX];
    int j;

    
    ctx = InitCTX();
    
    memset((char *)&serv_addr, 0, sizeof(serv_addr)); /*reset the serv_addr, then reassign*/
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    serv_addr.sin_port = htons(portInt);
    /* Create the socket. */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket (client)");
        return(1);
    }
    /* Connect to the server. */
    connectResult = connect(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr));
    if (connectResult < 0)
    {
        perror("Client did not connect to server");
        return(1);
    }
    /* connection was successfully established by this point*/

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, sockfd);    /* attach the socket descriptor */
    
  
    int sslConnect =  SSL_connect(ssl);
    if ( sslConnect <= 0 )   /* perform the connection */
    {
        fprintf(stderr, "error connecting to ssl\n");
        ERR_print_errors_fp(stderr);
        return;
    }
      
    fprintf(stderr, "Connected with %s encryption\n", SSL_get_cipher(ssl));
    
    VerifyCertTopic(ssl, chosenTopic);
    
    ShowCerts(ssl);

    fprintf(stderr, "we here now, in the main of client, after connecting to server\n");
    memset(s, 0, MAX); /*reset s*/
        
    int bytesRead = SSL_read(ssl, s, sizeof(char)*24);
    EndMessageCheck(s);
    fprintf(stderr, "%s" , s);
    
    /*fgets(clientName, MAXNAME, stdin);*/
    scanf("%s", clientName); 
    len = strlen(clientName);
    if(!(strchr(clientName, '\n')))
    {
            scanf("%*[^\n]");
            scanf("%*c");
    }
    else
    {
        if (clientName[len - 1] == '\n')
        clientName[len - 1] = 0;
    }   
     int sentBytes = SSL_write(ssl, clientName, sizeof(char)*MAX);

    memset(clientName, '\0', MAX);
    memset(s, 0, MAX);
    int firstOrNot = SSL_read(ssl, s, MAX);
    EndMessageCheck(s);
    fprintf(stderr, "%s" , s);
    fflush(stdout);
    memset(s, 0, MAX);
   
    char messageBuffer[MAX+MAX+5]; /*clientName and msg*/
    char readBuffer[205];
    FD_ZERO(&active_fd_set);
    FD_SET(sockfd, &active_fd_set);
    FD_SET(client_inputFD, &active_fd_set);
    FD_ZERO(&read_fd_set);
    for (;;)
    {
        read_fd_set = active_fd_set;
        
        socketCount = select(sockfd+1, &read_fd_set, NULL, NULL, &timeout);
        if (socketCount < 0)
        {
            perror("Select in client failed as no sockfd is ready");
            exit(1);
        }
        if(socketCount ==0 )
        {
            printf("Timeout!\n");
            fflush(stdout);
            exit(1);
        }
        for (i = 0; i < sockfd+1 && socketCount >0; i++)
        {
            if (FD_ISSET(i, &read_fd_set)) /*read or active*/
            {
                socketCount--;
                /*handling msgs*/
                if (i == client_inputFD)
                    {
                        memset(messageBuffer, 0, MAX+1);
                        fgets(messageBuffer, MAX, stdin);
                        messageBuffer[MAX] = '\0';
                        if(!(strchr(messageBuffer, '\n')))
                        {
                            scanf("%*[^\n]");
                            scanf("%*c");
                        }
                        else 
                        {
                            if (messageBuffer[len - 1] == '\n')
                            messageBuffer[len - 1] = 0;
                        }
                        if(messageBuffer[0] != "\0")
                        {
                            int msgBytes = SSL_write(ssl, messageBuffer, sizeof(char)*MAX);
                     
                        }
                    }
            
                else
                    {
                        memset(readBuffer, 0, MAX+MAX+5);
                        int sslReadRes = SSL_read(ssl, readBuffer, MAX+MAX+5);
                        EndMessageCheck(readBuffer);
                        fprintf(stderr, "%s", readBuffer);
                    }
            }
        }

    }
    free(chatRoomPorts);
    free(chatRoomTopics);
    free(chosenTopic);
    free(readBuffer);
    free(portC);
}

/*checks if server has shut down, then exits*/
int EndMessageCheck(char * c1)
{
    if(strcmp(c1, "End\0")==0)
    {
        fprintf(stderr, "msg was End, quitting\n");
        exit(0);
    }
    return 0;
}
/*registering with directory server to receive list of chatrooms, uses UDP*/

void registerWithDirectory()
{
    
    int index=0;
    SSL_CTX * ctxR;
    SSL *ssl;
    SSL_library_init();
    int                sockfdR;
    int connectResult;
    struct sockaddr_in cli_addr, serv_addr;
    char               s[MAX];
    int                response;
    int                nread;
    int client_inputFD = fileno(stdin);
    int                i;
    int clilen = sizeof(cli_addr);
    int servlen = sizeof(serv_addr);    

    char singleElement[MAX+15];
    char stillReceiving;

    ctxR = InitCTX();
    char request[126];
    chatRoomTopics = malloc(sizeof(char *)*10);
    chatRoomPorts = malloc(sizeof(char *)*10);
    int servCount = 0;
    char * portRead = malloc(sizeof(char)*5);

    struct timeval timeout;
    timeout.tv_sec=1200000;
    timeout.tv_usec=0;/*microsec*/

    /*memset(address to start filling memory at,
             value to fill it with,
             number of bytes to fill)*/
    memset((char *)&serv_addr, 0, sizeof(serv_addr)); /*reset the serv_addr, then reassign*/
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    serv_addr.sin_port        = htons(SERV_TCP_PORT);

    char sending [MAX+5];
    if ((sockfdR = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket directory server");
        exit(1);
    }

    /* Connect to the server. */
    connectResult = connect(sockfdR, (struct sockaddr *) &serv_addr,sizeof(serv_addr));
    if (connectResult < 0)
    {
        perror("Client did not connect to server");
        exit(1);
    }
    /* connection was successfully established by this point*/

    ssl = SSL_new(ctxR);
    SSL_set_fd(ssl, sockfdR);
    SSL_connect(ssl);
    VerifyCertTopic(ssl, "directoryServer");
    ShowCerts(ssl);

    memset(s, 0, MAX); /*reset s*/
    char * imClient = "Client";
    int sentIdentity = SSL_write(ssl, "Client", strlen(imClient));

    fprintf(stderr, "Here is a list of all available chat rooms, please enter an address from the following options:\n");
    /*If the user enters anything longer than the port number or
something that cant be parsed to a port number, the client will be
disconnected.*/

    do{
    chatRoomTopics[index] = malloc(sizeof(char) *(MAX+1));
    chatRoomPorts[index] = malloc(sizeof(char) *5);
    int receivedList = SSL_read(ssl, singleElement, sizeof(char)*MAX+15);
    stillReceiving=singleElement[0];
    int serverIndex;
    /*
    Tokenizing
    */
    char * first= malloc(sizeof(char));

    char* token = strtok(singleElement, ",");
    int counterT=0;
    int counterP=0;
    int counterTokenize=0;
    while (token != NULL) {
        if(counterTokenize==0)
        {
          strcpy(first, token);
        }
        else if(counterTokenize == 1)
        {
         fprintf(stderr,"Chat room topic is: %s\t", token);
         strcpy(chatRoomTopics[index], token);
        }
        else
        {
         fprintf(stderr,"Corresponding Address: %s\n", token);
         strcpy(chatRoomPorts[index], token);
        }
        counterTokenize++;
        
        token = strtok(NULL, ",");
    }
    index++;
    memset(singleElement, '\0', (MAX+15));
    } while(stillReceiving == 'g');
    globalIndex = index;
    fprintf(stderr, "Please choose a chat room to join by entering the port from the list above: \n");
    scanf("%s", portRead);
    portC = malloc(sizeof(char)*5);
    strcpy(portC, portRead);
    free(portRead);
    SSL_free(ssl);
    close(sockfdR);
    SSL_CTX_free(ctxR);
    return;
}