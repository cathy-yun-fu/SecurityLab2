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
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"

// BOB

#define PORT 8888

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define PASSWORD "password"

SSL_CTX* ctx;
BIO *bio_err;

SSL* ssl;

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

int berr_exit_cleanup(char *string, int sock, int s){
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  close(sock);
  close(s);
  exit(0);
}

void check_cert(SSL* ssl, X509 *peer)
{
  char peer_CN[256];
  char peer_email[256];
  /*Check the common name*/

  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_email, 256);

  printf(FMT_CLIENT_INFO, peer_CN, peer_email);
}

void initOpenSSL(){
  if(!bio_err){
    /* Global system initialization*/
    SSL_library_init(); /* encryption & hash algorithms for SSL */
    SSL_load_error_strings();  /* error strings */
    bio_err=BIO_new_fp(stdout,BIO_NOCLOSE); /* An error write context */
  }
}

void setupSSLContext(){
  ctx = SSL_CTX_new(SSLv23_server_method()); // sslv3 method
  if (! (SSL_CTX_use_certificate_chain_file(ctx,"./bob.pem"))){
    berr_exit("Couldn't load certificate");
  }
  if (! (SSL_CTX_use_PrivateKey_file(ctx,"./bob.pem", SSL_FILETYPE_PEM))){
    berr_exit("Couldn't load Private Key");
  }
  if (! (SSL_CTX_load_verify_locations(ctx,"./568ca.pem", 0))){
    berr_exit("Couldn't load CA Certificate");
  }

  SSL_CTX_set_default_passwd_cb(ctx, cb);
//  SSL_CTX_set_cipher_list()
//  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

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
      printf(FMT_INCOMPLETE_CLOSE);
      break;
    default:
      berr_exit(FMT_INCOMPLETE_CLOSE);
  }
}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;

  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
        fprintf(stderr,"invalid port number");
        exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }

  initOpenSSL();
  setupSSLContext();
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));

  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }

  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  }

  while(1){

    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }

    /*fork a child to handle the connection*/
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      SSL* ssl = SSL_new(ctx);
      SSL_set_fd(ssl,s);

      int r =0;
      if((r = SSL_accept(ssl))<=0) {
        printf(FMT_ACCEPT_ERR);
        switch(SSL_get_error(ssl, r)) {
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
            printf("Err_get_error: %lu\n", ERR_get_error());
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
        berr_exit_cleanup("accept error", sock, s);
      }

      X509 *peer;
      if((peer = SSL_get_peer_certificate(ssl)) != NULL) {
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
          berr_exit("Certificate does not verify");
        } else {
          check_cert(ssl, peer);
        }
      } else {
        printf("ERROR: ssl null\n");
      }

//      len = recv(s, &buf, 25/5, 0);
      len = SSL_read(ssl,buf,255);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      SSL_write(ssl, answer, strlen(answer));
//      send(s, answer, strlen(answer), 0);

      ssl_shutdown(ssl, s);

      // Cleanup
      SSL_free(ssl);
      close(s);
      return 0;
    }
  }

  close(sock);
  SSL_CTX_free(ctx);
  return 1;
}