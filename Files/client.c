#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "openssl/bio.h"
#include <openssl/bioerr.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

// ALICE

#define HOST "localhost"
#define PORT 8888

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

SSL_CTX* ctx;

void initOpenSSL(){
//  if (!bio_err) {
    SSL_library_init(); /* encryption & hash algorithms for SSL */
    SSL_load_error_strings(); /* error strings *
//    /* error write context ?*/
//    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE); // what is this used for?
//  }
}

void setupSSLContext(){
  ctx = SSL_CTX_new(SSLv23_client_method()); // sslv3 method
  if (! (SSL_CTX_use_certificate_chain_file(ctx,"./alice.pem"))){
    perror("Couldn't load certificate");
  }
  if (! (SSL_CTX_use_PrivateKey_file(ctx,"./alice.pem"))){
    perror("Couldn't load Private Key");
  }
  if (! (SSL_CTX_load_verify_locations(ctx,"./568ca.pem", "\0"))){
    perror("Couldn't load CA Certificate");
  }

  SSL_CTX_set_default_passwd_cb(ctx, "password");

  // limit to SSLv3 and TLS
  SSL_CTX_set_options(ctx, SSL_OP_NO_DTLSv1);
  SSL_CTX_set_options(ctx, SSL_OP_NO_DTLSv1_2);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  printf(FMT_OUTPUT, "Successfully set up SSL_CTX Object", "\0");

}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  // OpenSSL setup
  initOpenSSL();
  setupSSLContext();

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");

  /* connected */



  send(sock, secret, strlen(secret),0);
  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);

  close(sock);
  return 1;
}
