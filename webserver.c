#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define PORT 443
#define LISTENQ 23 // Cola de espera para los clientes
#define BUFFERSIZE 8096

#define FAIL -1

int OpenListener(int port)
{ int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

SSL_CTX* InitServerCTX(void)
{ SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
    SSL_load_error_strings(); /* load all error messages */
    method = SSLv23_server_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method); /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
 /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl)
{ X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{ char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

    if ( SSL_accept(ssl) == FAIL ) /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl); /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf); /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl); /* get socket connection */
    SSL_free(ssl); /* release SSL state */
    close(sd); /* close connection */
}
/*main*/

void web (int);

int main (int count, char *strings[])
{
int listenfd, socketfd, pid;
socklen_t length;
static struct sockaddr_in serv_addr;
static struct sockaddr_in cli_addr;
 SSL_CTX *ctx;
    int server;
    char *portnum;

    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
// Se crea el socket de escuaha
listenfd = socket (AF_INET, SOCK_STREAM, 0);

serv_addr.sin_family = AF_INET;
serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
serv_addr.sin_port = htons (PORT);

// Se asociamos la direccion con el socket
bind (listenfd, (struct sockaddr *) &serv_addr, sizeof (serv_addr));

listen (listenfd, LISTENQ);
//aaaa

    SSL_library_init();

    portnum = strings[1];

    ctx = InitServerCTX(); /* initialize SSL */

    LoadCertificates(ctx, "cert.pem", "key.pem"); /* load certs */

    server = OpenListener(atoi(portnum)); /* create server socket */

    while (1)
    { struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len); /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx); /* get new SSL state with context */
        SSL_set_fd(ssl, client); /* set connection socket to SSL state */
        Servlet(ssl); /* service connection */
for (; ;) {
length = sizeof (cli_addr);
//socketfd = accept (listenfd, (struct sockaddr *) &cli_addr, &length);
socketfd = accept (listenfd, (struct sockaddr *) &cli_addr, &length);
if ((pid = fork ()) == 0) {
close (listenfd);
web (socketfd);
} else {
close (socketfd);
}
}
    }
    close(server); /* close server socket */
    SSL_CTX_free(ctx); /* release context */




}

void
web (int fd)
{
int i, file_fd;
long ret, size;
static char buffer[BUFFERSIZE+1];
struct stat st;
char * ext;

ret = read (fd, buffer, BUFFERSIZE);

// Si leemos un numero de bytes menor al tamano del buffer, pongo el caracter de terminacion
if (ret > 0 && ret < BUFFERSIZE) {
buffer[ret] = 0;
} else {
buffer[0] = 0;
}

// verifico que el navegador nos envia la instruccion GET
if (strncmp (buffer, "GET ", 4) == 0) {
for (i = 4; i < BUFFERSIZE; i++) {
if (buffer[i] == ' ') {
buffer[i] = 0;
break;
}
}

// Verifico que el usuario especifico una pagina, si no lo mando al index
if (!strncmp (&buffer[0], "GET /\0", 6)) {
strcpy (buffer, "GET /index.html");
}

// Se abre el archivo, si no existe se abre el de error
if ((file_fd = open (&buffer[5], O_RDONLY)) == -1) {
file_fd = open ("404.html", O_RDONLY);
fstat (file_fd, &st);
size = st.st_size;
sprintf (buffer, "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\nContent-Lenhttp://localhost/test.htmlhttp://localhost/test.htmlgth: %ld\r\n\r\n",size);

} else { // Si el archivo existe se muestra el contenido
fstat (file_fd, &st);
size = st.st_size;


ext = strstr(buffer,".");
ext = ext+1;
fprintf(stderr,"%s",ext);
if(strcmp("html",ext)==0){

sprintf (buffer, "HTTP/1.1 200 OK\r\nContent-Type: text/html \r\nContent-Length: %ld\r\n\r\n", size);
} else if(strcmp("jpg",ext)==0){

sprintf (buffer, "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg \r\nContent-Length: %ld\r\n\r\n", size);
} else if (strcmp("txt",ext)==0){

sprintf (buffer, "HTTP/1.1 200 OK\r\nContent-Type: text/plain \r\nContent-Length: %ld\r\n\r\n", size);
} else{

sprintf (buffer, "HTTP/1.1 200 OK\r\nContent-Type: unknown/unknown \r\nContent-Length: %ld\r\n\r\n", size);
}
}

write (fd, buffer, strlen (buffer));

// Obtenemos el archivo completo para poder cerrar el socket
while ((ret = read (file_fd, buffer, BUFFERSIZE)) > 0 ) {
write (fd, buffer, ret);
}
}

sleep (1);
exit (1);
}
