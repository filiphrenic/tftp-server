#ifndef MREPRO_FH
#define MREPRO_FH

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>           /* chmod, stat */
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/select.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>   /* network types */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/ip_icmp.h>    /* struct icmp, icmphdr */

#include <poll.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

// ===========================================================================

int is_daemon;

typedef unsigned char byte;
typedef void Sigfunc(int);

typedef void TCPFunc(int);
#define TRY(f,s) if (f != NULL) f(s);

// MACROS
#define FOR(i,n) for ( i=0; i<(n); ++i )
#define MLC(t,n) ((t*) malloc(n * sizeof(t)))
#define CLC(t,n) ((t*) calloc(n * sizeof(t)))

// arithmetic
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define ABS(a)   ((a) >  0  ? (a) : -(a))
#define SIGN(x)  (((x) > 0) - ((x) < 0))

// bit manipulation
#define SET_BIT(mask, bit)     ((mask) |=  (1<<(bit)))
#define CLEAR_BIT(mask, bit)   ((mask) &= ~(1<<(bit)))
#define TOGGLE_BIT(mask, bit)  ((mask) ^=  (1<<(bit)))
#define ISSET_BIT(mask, bit) !!((mask) &   (1<<(bit)))

// errors
#define MP_PARAM_ERR 1
#define MP_ADDR_ERR 2
#define MP_SOCK_ERR 3
#define MP_COMM_ERR 4
#define MP_RUNT_ERR 5

#define BUFFER_LEN 1024
#define IP_LEN 50
#define PORT_LEN 10
#define BACKLOG 10

void Getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);
void Getnameinfo(const struct sockaddr*, socklen_t, char*, size_t, char*, size_t, int);
int Getpeername(int, struct sockaddr*, socklen_t*);
void* In_addr(const struct sockaddr*);
in_port_t In_port(const struct sockaddr*);

/*****************************************************************************
 *                                                                           *
 *                                 Wrappers                                  *
 *                                                                           *
 *****************************************************************************/

void* Malloc(size_t);
void* Calloc(size_t);
pid_t Fork();
void Daemon(int,int);
Sigfunc* signal(int, Sigfunc*);
Sigfunc* Signal(int, Sigfunc*);
void Errx(int, const char*, ...);
void Warnx(const char*, ...);

/*****************************************************************************
 *                                                                           *
 *                                 Connection                                *
 *                                                                           *
 *****************************************************************************/

int Socket(int, int, int);
void Bind(int, const struct sockaddr*, socklen_t);
void Close(int);

/*****************************************************************************
 *                                                                           *
 *                                 UDP                                       *
 *                                                                           *
 *****************************************************************************/

 int UDPserver(const char*);

/*****************************************************************************
 *                                                                           *
 *                                 TCP                                       *
 *                                                                           *
 *****************************************************************************/

 typedef struct {
     int socket;
     TCPFunc* func;
 } tcp_client_args;

void Listen(int, int);
int Accept(int, struct sockaddr* restrict, socklen_t* restrict);
void Connect(int, const struct sockaddr*, socklen_t);
char* GetIP(const struct sockaddr*);
char* GetClientInfo(int, u_short*);
void ReadStringUntil(int, char*, int, char);
void WriteString(int, const char*);
void ReadFileFrom(int, const char*, const char*);
void TransferFile(int, const char*, uint32_t);
int TCPserver(const char*, int);
int TCPclient(const char*, const char*);
void TCPserverUsage(const char*);
int RunTCPserver(int, char**, const char*,
    TCPFunc*, const char*, int);

/*****************************************************************************
 *                                                                           *
 *                            Send/Recieve                                   *
 *                                                                           *
 *****************************************************************************/

 ssize_t Send(int, const void*, size_t, int);
 ssize_t Recv(int, void*, size_t, int);

ssize_t Sendto(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
ssize_t Recvfrom(int, void*, size_t, int, struct sockaddr*, socklen_t*);

ssize_t Writen(int, const void*, size_t);
ssize_t Readn(int, void*, size_t);

/*****************************************************************************
 *                                                                           *
 *                              Socket options                               *
 *                                                                           *
 *****************************************************************************/

void Setsockopt(int, int, int, const void *, socklen_t);
void SetTimeout(int, int, int);
void SetReuseAddr(int);
void SetBroadcast(int);
void SetTTL(int,int);

/*****************************************************************************
 *                                                                           *
 *                                 ICMP                                      *
 *                                                                           *
 *****************************************************************************/

u_short in_cksum(u_short*, int);
void* GetICMPData(const void*, size_t, u_short);
struct icmp* FillICMP(void*, u_short, u_short, u_short*);

#endif // MREPRO_FH
