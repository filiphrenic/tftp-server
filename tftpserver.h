#include "mrepro.h"

#define LOG_NAME "fh47758:MrePro tftpserver"

#define ROOT_DIR "/tftpboot"

#define BLOCK_SIZE 512

#define NO_RETRANS 3  // retransmitions
#define TIMEOUT_SEC 3 // seconds
#define TIMEOUT_MSC 0 // microseconds

// opcode
#define TFTP_RRQ    1
#define TFTP_WRQ    2
#define TFTP_DATA   3
#define TFTP_ACK    4
#define TFTP_ERROR  5

// error
#define TFTP_ER_NOTDEF     0
#define TFTP_ER_NOTFOUND   1
#define TFTP_ER_ACCESS     2
#define TFTP_ER_DISKFULL   3
#define TFTP_ER_ILLEGAL    4
#define TFTP_ER_PORT       5
#define TFTP_ER_EXISTS     6
#define TFTP_ER_USER       7

const byte ZERO = 0;

typedef struct {
    u_short opcode;
    char* filename;
    char* original_filename;
    byte binary;
    struct sockaddr* addr;
    u_short tid;
} tftp_request;

typedef struct {
    u_short opcode;
    u_short code;
    byte block[BLOCK_SIZE];
} tftp_packet;

void Usage(const char* name){
    Errx(MP_PARAM_ERR, "Usage: %s [-d] port_name_or_number", name);
}
