#include "mrepro.h"

void Getaddrinfo(const char* hostname, const char* servicename,
                    const struct addrinfo* hints, struct addrinfo** result)
{
    int error;
    error = getaddrinfo(hostname, servicename, hints, result);
    if (error) Errx(MP_ADDR_ERR, "getaddrinfo: %s", gai_strerror(error));
}
void Getnameinfo(const struct sockaddr* sockaddr, socklen_t addrlen,
                    char* host, size_t hostlen, char* serv, size_t servlen,
                    int flags)
{
    int error;
    error = getnameinfo(sockaddr, addrlen, host, hostlen, serv, servlen, flags);
    if (error) Errx(MP_ADDR_ERR, "getnameinfo: %s", gai_strerror(error));
}
int Getpeername(int socket, struct sockaddr* addr, socklen_t* addrlen){
    int error;
    error = getpeername(socket, addr, addrlen);
    if (error) Errx(MP_ADDR_ERR, "getpeername: %s", gai_strerror(error));
    return error;
}

// get sockaddr, IPv4 or IPv6:
void* In_addr(const struct sockaddr *sa){
    u_short family = sa->sa_family;
    if (family == AF_INET)
	return     &(( (struct sockaddr_in*)  sa)->sin_addr);
    return     &(( (struct sockaddr_in6*) sa)->sin6_addr);
}

u_short In_port(const struct sockaddr *sa){
    u_short family = sa->sa_family;
    if (family == AF_INET)
	return          ( (struct sockaddr_in*)  sa)->sin_port;
    return (u_short)( (struct sockaddr_in6*) sa)->sin6_port;
}

/*****************************************************************************
 *                                                                           *
 *                                 Wrappers                                  *
 *                                                                           *
 *****************************************************************************/

 void* Malloc(size_t size){
 	void* ptr;
 	if ((ptr = malloc(size)) == NULL)
 		Errx(MP_RUNT_ERR, "malloc: %s", strerror(errno));
 	return ptr;
 }

 void* Calloc(size_t size){
 	void* ptr;
 	if ((ptr = calloc(1, size)) == NULL)
 		Errx(MP_RUNT_ERR, "calloc: %s", strerror(errno));
 	return ptr;
 }

 pid_t Fork(){
     pid_t pid;
     if ((pid=fork()) == -1)
         Errx(MP_RUNT_ERR, "fork: %s", strerror(errno));
     return pid;
 }

void Daemon(int nochdir, int noclose){
    if (Fork()) _exit(0);
    umask(0);
    if (setsid() < 0)
        Errx(MP_RUNT_ERR, "%s", strerror(errno));
    Signal(SIGHUP, SIG_IGN);
    if (Fork()) _exit(0);

    if (!nochdir){
        if (chdir("/") < 0)
            Warnx("%s", strerror(errno));
    }

    if (!noclose){
        close(0); // stdin
        close(1); // stdout
        close(2); // stderr
        open("/dev/null", O_RDONLY); /* stdin > /dev/null */
        open("/dev/null", O_RDWR); /* stdout > /dev/null */
        open("/dev/null", O_RDWR); /* stderr > /dev/null */
    }

    is_daemon = 1;
}

Sigfunc* signal(int signo, Sigfunc* func){
	struct sigaction act, oact;
	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
}

Sigfunc* Signal(int signo, Sigfunc* func){
	Sigfunc *sigfunc;
	if ((sigfunc = signal(signo, func)) == SIG_ERR)
		Errx(MP_RUNT_ERR, "signal: %s", strerror(errno));
	return sigfunc;
}

void Errx(int status, const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    if (is_daemon) {
        vsyslog(LOG_ALERT, fmt, args);
        _exit(status);
    } else
        verrx(status, fmt, args);
    va_end(args);
}

void Warnx(const char* fmt, ...){
    va_list args;
    va_start(args, fmt);
    if (is_daemon)
        vsyslog(LOG_INFO, fmt, args);
    else
        vwarnx(fmt, args);
    va_end(args);
}

/*****************************************************************************
 *                                                                           *
 *                                 Connection                                *
 *                                                                           *
 *****************************************************************************/

int Socket(int family, int type, int protocol){
    int sfd = socket(family, type, protocol);
    if (sfd < 0) Errx(MP_SOCK_ERR, "socket: %s", strerror(errno));
    return sfd;
}

void Bind(int socket, const struct sockaddr* sockaddr, socklen_t addrlen){
    int error = bind(socket, sockaddr, addrlen);
    if (error < 0) {
        Close(socket);
        Errx(MP_SOCK_ERR, "bind: %s", strerror(errno));
    }
}

void Close(int socket){
    int error;
    error = shutdown(socket, SHUT_RDWR);
    // if (error < 0) Warnx("shutdown: %s", strerror(errno));
    error = close(socket);
    // if (error < 0) Warnx("close: %s", strerror(errno));
}

/*****************************************************************************
 *                                                                           *
 *                                 UDP                                       *
 *                                                                           *
 *****************************************************************************/

 int UDPserver(const char* port){
     struct addrinfo hints, *res;
     int socket;

     memset(&hints, 0, sizeof(hints));
     hints.ai_family   = AF_INET;
     hints.ai_flags    = AI_PASSIVE;
     hints.ai_socktype = SOCK_DGRAM;

     // create socket
     Getaddrinfo(NULL, port, &hints, &res);
     socket = Socket(res->ai_family, res->ai_socktype, res->ai_protocol);
     Bind(socket, res->ai_addr, res->ai_addrlen);

     freeaddrinfo(res);

     return socket;
 }

/*****************************************************************************
 *                                                                           *
 *                                 TCP                                       *
 *                                                                           *
 *****************************************************************************/

void Listen(int socket, int backlog){
    if (listen(socket, backlog)) {
        Close(socket);
        Errx(MP_COMM_ERR, "listen: %s", strerror(errno));
    }
}

int Accept(int socket, struct sockaddr* restrict cliaddr, socklen_t* restrict addrlen){
    int client = accept(socket, cliaddr, addrlen);
    if (client==-1) Errx(MP_COMM_ERR, "accept: %s", strerror(errno));
    return client;
}

void Connect(int socket, const struct sockaddr* server, socklen_t addrlen){
    if (connect(socket,server,addrlen)) {
        Close(socket);
        Errx(MP_COMM_ERR, "connect: %s", strerror(errno));
    }
}

char* GetIP(const struct sockaddr* addr){
    char* ip = MLC(char, IP_LEN);
    u_short f = addr->sa_family;
    inet_ntop(f, In_addr(addr), ip, IP_LEN);
    return ip;
}

char* GetClientInfo(int socket, u_short* port){
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);
    Getpeername(socket, &addr, &addrlen);
    if (port != NULL)
        *port = ntohs(In_port(&addr));

    return GetIP(&addr);
}

void ReadStringUntil(int socket, char* ptr, int size, char end){
	ssize_t readBytes = 1;
	int i, idx=0;
	while (readBytes > 0){
            readBytes = Recv(socket, ptr + idx, size-idx, 0);
            for (i = 0; i < readBytes; i++) {
                if (*(ptr + idx + i) == end) {
					ptr[idx+i+1] = 0;
					i = readBytes + 2; // hack
				}
            }
            if (i > readBytes) break;
    }
}

void WriteString(int socket, const char* str){
    Writen(socket, str, strlen(str) + 1);
}

void ReadFileFrom(int socket, const char* path, const char* fopen_mode){
    FILE* file;
    int len;
    byte* buffer;

    file = fopen(path, fopen_mode);
    buffer = MLC(byte, BUFFER_LEN);

    while( ( len = Readn(socket, buffer, BUFFER_LEN) ) > 0 )
        fwrite(buffer, sizeof(byte), len, file);
    fclose(file);
}

void TransferFile(int socket, const char* path, uint32_t offset){
    FILE* file = fopen(path, "rb");
    byte* buffer = MLC(byte, BUFFER_LEN);
    int len;

    fseek(file, offset, SEEK_SET);

    while( (len = fread(buffer, sizeof(byte), BUFFER_LEN, file)) > 0 ){
        Writen(socket, buffer, len);
    }
    fclose(file);
    free(buffer);
}

int TCPserver(const char* port, int backlog){
	struct addrinfo hints, *res;
	int socket;

	memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    Getaddrinfo(NULL, port, &hints, &res);

    socket = Socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    Bind(socket, res->ai_addr, res->ai_addrlen);
    Listen(socket, backlog);
    SetReuseAddr(socket);
    freeaddrinfo(res);

    return socket;
}

int TCPclient(const char* host, const char* port){
    int socket;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    Getaddrinfo(host, port, &hints, &res);
    socket = Socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    Connect(socket, res->ai_addr, sizeof(struct sockaddr));

    return socket;
}

void TCPserverUsage(const char* name){
    Errx(MP_PARAM_ERR, "Usage: %s [-p port]", name);
}

void* ClientThread(void* thread_args){
    tcp_client_args* args = (tcp_client_args*) thread_args;
    args->func(args->socket);
    Close(args->socket);
    pthread_exit(0);
}

int RunTCPserver(int argc, char** argv, const char* port_default,
    TCPFunc* process, const char* pname, int facility){

    // options
    char* port = MLC(char, PORT_LEN);
    char ch;

    // connection
    int server_sock, client_sock;
    struct sockaddr client;
    socklen_t client_len;

    // threads
    tcp_client_args* args;
    pthread_t tid;

    // init options
    strcpy(port, port_default);
    while ( (ch=getopt(argc, argv, "p:")) != -1 ){
        if (ch == 'p') strcpy(port, optarg);
        else TCPserverUsage(argv[0]);
    }
    if (argc - optind != 0) TCPserverUsage(argv[0]);


    if (pname != NULL){
        Daemon(1, 0);
        openlog(pname, LOG_PID, facility);
    }

    server_sock = TCPserver(port, BACKLOG);

    while(1){
        client_sock = Accept(server_sock, &client, &client_len);
        args = MLC(tcp_client_args, 1);
        args->socket = client_sock;
        args->func = process;
        pthread_create(&tid, NULL, ClientThread, (void*) args);
    }

    // release resources
    Close(server_sock);
    free(port);
    return 0;
}

/*****************************************************************************
 *                                                                           *
 *                            Send/Recieve                                   *
 *                                                                           *
 *****************************************************************************/

ssize_t Send(int socket, const void *buffer, size_t length, int flags){
    int status = send(socket, buffer, length, flags);
    if (status<0) Warnx("send: %s", strerror(errno));
    return status;
}

ssize_t Recv(int socket, void *buffer, size_t length, int flags){
    int status = recv(socket, buffer, length, flags);
    if (status<0) Warnx("recv: %s", strerror(errno));
    return status;
}

ssize_t Sendto(int sockfd, const void* buff, size_t nbytes, int flags, const struct sockaddr* to, socklen_t addrlen){
    int status = sendto(sockfd, buff, nbytes, flags, to, addrlen);
    if (status == -1) Warnx("sendto: %s", strerror(errno));
    return status;
}

ssize_t Recvfrom(int sockfd, void* buff, size_t nbytes, int flags, struct sockaddr* from, socklen_t* addrlen){
    int status = recvfrom(sockfd, buff, nbytes, flags, from, addrlen);
    if (status == -1) Warnx("recvfrom: %s", strerror(errno));
    return status;
}

ssize_t Writen(int fd, const void *vptr, size_t n){
    size_t nleft = n;
    ssize_t nwritten;
    const char *ptr = vptr;

    while (nleft > 0) {
        if ( (nwritten = write(fd, ptr, nleft)) < 0) {
            if (nwritten<0 && errno == EINTR)
                nwritten = 0;
            else
                return -1;
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    return n;
}

ssize_t Readn(int fd, void *vptr, size_t n){
    size_t nleft = n;
    ssize_t nread;
    char *ptr = vptr;

    while (nleft > 0) {
        if ( (nread = read(fd, ptr, nleft)) < 0) {
            if (nread<0 && errno == EINTR)
                nread = 0;
            else
                return -1;
        } else if (nread == 0) break;
        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft);
}

/*****************************************************************************
 *                                                                           *
 *                              Socket options                               *
 *                                                                           *
 *****************************************************************************/

void Setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen){
	if (setsockopt(s, level, optname, optval, optlen) == -1)
		Warnx("setsockopt %s:", strerror(errno));
}

void SetTimeout(int sfd, int seconds, int microseconds){
    struct timeval waiting = {seconds, microseconds};
    Setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &waiting, sizeof(waiting));
    // istek => errno = EAGAIN
}

void SetReuseAddr(int sfd){
    int on=1;
    Setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

void SetBroadcast(int sfd){
	int on = 1;
	Setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
}

void SetTTL(int sfd, int ttl){
	Setsockopt(sfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

/*****************************************************************************
 *                                                                           *
 *                                 ICMP                                      *
 *                                                                           *
 *****************************************************************************/

// icmp
u_short in_cksum(u_short* addr, int len){
    int nleft = len;
    int sum = 0;
    u_short *w = addr;
    u_short  answer = 0;

    /* U 32 bitni akumulator sum dodajemo 16 bitne rijeci
    * Na kraju premjestimo sve carry bitove na donjih 16 bitova
    */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* ako je neparni broj okteta ... */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    /* dodaj carry bitove (gornjih 16) na donjih 16 bitova */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);	/* jos jednom dodaj carry ako se pojavio*/
    answer = ~sum;	/* treba mi 1-komplement donjih 16 bitova */
    return (answer);
}

void* GetICMPData(const void* ptr, size_t len, u_short id){
    int hlen1, icmplen;
    struct ip *ip; /* netinet/ip.h */
    struct icmp *icmp; /* netinet/ip_icmp.h */

    ip = (struct ip *)ptr; /* pocetak IP zaglavlja */
    hlen1 = ip->ip_hl << 2; /* duzina IP zaglavlja */

    icmp = (struct icmp *)(ptr + hlen1); /* pocetak ICMP zaglavlja */
    if ((icmplen = len - hlen1) < 16)
        Errx(MP_RUNT_ERR, "icmplen (%d) < 16", icmplen);
    if (icmp->icmp_type == ICMP_ECHOREPLY) {
        if (icmp->icmp_id != id)
            return NULL; /* nije odgovor na nass ECHO_REQUEST */
    }
    return icmp->icmp_data;
}

struct icmp* FillICMP(void* data, u_short datalen, u_short id, u_short* nsent){
    int len;
    struct icmp *icmp;

    len = 8 + datalen;
    icmp = (struct icmp*) Calloc(len);
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = id;
    icmp->icmp_seq = (*nsent)++;
    memcpy(icmp->icmp_data, data, datalen);

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

    return icmp;
}
