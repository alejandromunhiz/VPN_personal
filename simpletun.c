/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/aes.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

#if defined CESAR
/**************************************************************************
 * Uso: funciones de cifrado y descifrado Cesar.                          *
 **************************************************************************/
#define CAESAR_CYPHER 1
#define CAESAR_DECYPHER 0
void cifrado_cesar(int N, char* texto, int cifrado, int size){
	if (cifrado){
		for (int i=0; i<size; i++){
			texto[i] = (texto[i] + N) % 256;
		}
	}else{
	        for (int i=0; i<size; i++)
	                texto[i] = (texto[i] + 256 - N) % 256;
        }
}
#endif


void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	
	for (; i<len; ++i)
		printf("%02X ", *p++);
	
	printf("%d\n", len);
}




int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
      perror("connect()");
      exit(1);
    }

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  } else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    if (listen(sock_fd, 5) < 0){
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;


#if defined AES
  /* Definimos un vector inicial (IV) y una clave de 128bits */
  unsigned char iv[AES_BLOCK_SIZE];
  const unsigned char aes_key[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
  char buffer_encriptado[BUFSIZE];
  AES_KEY enc_key, dec_key;
//  AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
//  AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key);

#endif

/* A manera informativa, indicamos el modo que se está ejecutando */
#if defined CESAR
      printf("\n\nSIMPLETUN + CIFRADO CESAR\n\n");
#elif defined AES
      printf("\n\nSIMPLETUN + ENCRIPTADO AES 128\n\n"); 
#else
      printf("\n\nSIMPLETUN POR DEFECTO\n\n");
#endif



  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }




    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);


#if defined CESAR       
/*Si al compilar definimos CESAR, se cifrará el código con una clave 88 y se guardará en el mismo buffer*/
      	cifrado_cesar(88, buffer, CAESAR_CYPHER, nread);
#elif defined AES 
/*Si al compilar definimos AES, se reiniciarán iv y dec_key y se encriptará buffer en buffer_encriptado */
/*Adaptamos el tamaño del mensaje para el AES */
	int nread2 = nread + 16 - (nread % 16);
	if ((nread % 16) != 0) {   
		for (int i=nread; i<nread2; i++) buffer[i]=0;
    	}else{ 
		nread2 = nread;}
	          printf("NET2TAP %lu: Read %d bytes from the tap\n", net2tap, nread);
	          printf("NET2TAP %lu: Emited %d bytes to the network\n", net2tap, nread2);
	memset(iv, 0x00, AES_BLOCK_SIZE);
  	AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
//	print_data("Buffer original", buffer, nread);
  	AES_cbc_encrypt(buffer, buffer_encriptado, nread2, &enc_key, iv, AES_ENCRYPT);
//	print_data("Buffer modificado", buffer_encriptado, nread);
//	memset(iv, 0x00, AES_BLOCK_SIZE); 
 //	AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key);
//  	AES_cbc_encrypt(buffer_encriptado, buffer, nread, &dec_key, iv, AES_DECRYPT);
//	print_data("Buffer original", buffer, nread);

#endif

      /* write length + packet */
      plength = htons(nread);
      nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
/*Si se ha usado cifrado AES, se envía el buffer encriptado. */
#if defined AES
      nwrite = cwrite(net_fd, buffer_encriptado, nread2);
#else
      nwrite = cwrite(net_fd, buffer, nread);
#endif   

      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }






    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */
           
      nread = read_n(net_fd, (char *)&plength, sizeof(plength));	/* Read length */ 
      if(nread == 0) break;	/* ctrl-c at the other end */

      net2tap++;

/*Según sea AES o no, se guarda la lectura en un buffer u otro. */     
#if defined AES
      nread = read_n(net_fd, buffer_encriptado, ntohs(plength));
#else
      nread = read_n(net_fd, buffer, ntohs(plength));
#endif

      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

#if defined CESAR
/*Si al compilar definimos CESAR, se descifrará el mensaje con una clave 88 */
      cifrado_cesar(88, buffer, CAESAR_DECYPHER, nread);
#elif defined AES
/*Si al compilar definimos AES, se reiniciarán iv y dec_key y se desencriptará buffer_encriptado */
/*Adaptamos el tamaño del mensaje para el AES */
	int nread2 = nread + 16 - (nread % 16);
	if ((nread % 16) != 0) {   
		for (int i=nread; i<nread2; i++) buffer[i]=0;
    	}else{ 
		nread2 = nread;}
	memset(iv, 0x00, AES_BLOCK_SIZE); 
 	AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key);
  	AES_cbc_encrypt(buffer_encriptado, buffer, nread2, &dec_key, iv, AES_DECRYPT);	
	nread = nread2;
#endif
/*Si no se define nada, se enviará el texto en plano */
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
   }




  }
  
  return(0);
}
