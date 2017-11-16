#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

#include <unistd.h> // test
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

// openssl version 1.0.1e-fips

#define PASSWORD "password"

SSL_CTX* ctx;
BIO* bio_err = 0;
BIO *sbio;
SSL *ssl;

static int cb(char *buf,int num, int rwflag,void *userdata)
{
  if (num < strlen(PASSWORD)+1) return(0);
  strcpy(buf,PASSWORD);
  return(strlen(PASSWORD));
}

int berr_exit(char *string) {
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  exit(0);
}

int berr_exit_cleanup(char *string, int sock) {
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  close(sock);
  exit(0);
}

void check_cert(SSL* ssl, X509 *peer)
{
  char peer_CN[256];
  char peer_email[256];
  char cert_issuer[256];
  if(SSL_get_verify_result(ssl)!=X509_V_OK) {
    berr_exit(FMT_NO_VERIFY);
  }
  /*Check the common name*/
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
  if(strcasecmp(peer_CN, "Bob's Server")) {
    berr_exit(FMT_CN_MISMATCH);
  }
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_email, 256);
  if(strcasecmp(peer_email, "ece568bob@ecf.utoronto.ca")) {
    berr_exit(FMT_EMAIL_MISMATCH);
  }
  X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),NID_commonName, cert_issuer, 256);
  printf(FMT_SERVER_INFO, peer_CN, peer_email, cert_issuer);
}

void initOpenSSL(){
  if(!bio_err){
    /* Global system initialization*/
    SSL_library_init();
    SSL_load_error_strings();
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE); /* An error write context */
  }
}

void setupSSLContext(){
  const SSL_METHOD* meth = SSLv23_client_method();
  ctx = SSL_CTX_new(meth); // sslv3 method
  if (! (SSL_CTX_use_certificate_chain_file(ctx,"./alice.pem"))){
    berr_exit("Couldn't load certificate");
  }
  if (! (SSL_CTX_use_PrivateKey_file(ctx,"./alice.pem", SSL_FILETYPE_PEM)) ){
    berr_exit("Couldn't load Private Key");
  }
  if (! (SSL_CTX_load_verify_locations(ctx,"./568ca.pem", 0))){
    berr_exit("Couldn't load CA Certificate");
  }
  SSL_CTX_set_default_passwd_cb(ctx, cb);
  SSL_CTX_set_cipher_list(ctx, "SHA1");

  // limit to SSLv3 and TLS
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

#if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
  SSL_CTX_set_verify_depth(ctx,1);
#endif
}

void ssl_shutdown(SSL* ssl, int s) {
  int r = SSL_shutdown(ssl);
  while (!r) {
    /* If we called SSL_shutdown() first then
       we always get return value of '0'. In
       this case, try again, but first send a
       TCP FIN to trigger the other side's
       close_notify*/
    shutdown(s, 1);
    r = SSL_shutdown(ssl);
  }
  switch (r) {
    case 1:
      printf("shutdown succeed\n");
      break; /* Success */
    case -1:
      printf(FMT_INCORRECT_CLOSE);
      break;
    default:
      berr_exit(FMT_INCORRECT_CLOSE);
  }
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

  // OpenSSL setup
  initOpenSSL();
  setupSSLContext();

  /* TCP Starts */
  /*get ip address of the host*/
  host_entry = gethostbyname(host);

  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);

  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

  /* open socket */

  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0) {
    perror("socket");
//    printf(FMT_OUTPUT, "Socket Error","\0");
    berr_exit_cleanup("socket error", sock);
  }
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0) {
    perror("connect");
//    printf(FMT_OUTPUT, "Connect Error","\0");
    berr_exit_cleanup("connect error", sock);
  }

  /* TCP Connected */

  // Attach SSL to socket
  ssl=SSL_new(ctx);
  SSL_set_fd(ssl,sock);

  sbio=BIO_new_socket(sock,BIO_NOCLOSE);
  SSL_set_bio(ssl,sbio,sbio);

  int r = 0;
  if((r = SSL_connect(ssl))<=0) { // error
    printf("%i\n",r);
    int j =0;
    switch((j = SSL_get_error(ssl, r))) {
      case SSL_ERROR_NONE:
        printf("ssl_error_none\n");
        printf("Err_get_error: %lu\n", ERR_get_error());
        break;
      case SSL_ERROR_ZERO_RETURN:
        printf("ssl_error_zero_return\n");
        printf("Err_get_error: %lu\n", ERR_get_error());
        break;
      case SSL_ERROR_SYSCALL:
        printf("ssl_error_syscall\n");
        printf("Err_get_error: %lu", ERR_get_error());
        break;
      case SSL_ERROR_SSL:
        printf("ssl_error_ssl\n");
        printf("Err_get_error: %lu\n", ERR_get_error());
        break;
      case SSL_ERROR_WANT_READ:
        printf("ssl_error_want_read\n");
        printf("Err_get_error: %lu\n", ERR_get_error());
        break;
      default:
        printf("unknown error!\n");
        printf("Err_get_error: %lu\n", ERR_get_error());
        break;
    }
    printf("%d\n",j);
    printf(FMT_CONNECT_ERR);
    berr_exit_cleanup("accept error", sock);
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,  0);
  X509 *peer;
  if((peer = SSL_get_peer_certificate(ssl)) != NULL) {
    check_cert(ssl, peer);
  }

  SSL_write(ssl, secret, strlen(secret));
//  send(sock, secret, strlen(secret),0);
  len = SSL_read(ssl,buf,255);
//  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';

  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  ssl_shutdown(ssl, sock);
  close(sock);
  SSL_free(ssl);;
  SSL_CTX_free(ctx);
  return 1;
}