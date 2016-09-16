#include "tftpserver.h"

typedef struct {
	FILE* file;
	byte* buff;
	int offset;
	byte binary;
} file_reader;

file_reader* createReader(const char* filename, byte binary){
	file_reader* fr = MLC(file_reader, 1);
	fr->file = fopen(filename, "rb");
	fr->buff = MLC(byte, 2*BLOCK_SIZE);
	fr->offset = 0;
	fr->binary = binary;
	return fr;
}

void destroyReader(file_reader* fr){
	fclose(fr->file);
	free(fr->buff);
	free(fr);
}

size_t readFromReader(file_reader* fr, byte* buffer){
	byte* helper = MLC(byte, BLOCK_SIZE);
	int i,j,m;
	int n = BLOCK_SIZE - (fr->offset+1)/2;
	size_t size;

	m = fread(helper, sizeof(byte), n, fr->file);
	for(i=0,j=fr->offset; i<m; i++){
		if (!fr->binary && helper[i]=='\n'){
			fr->buff[j++] = '\r';
		}
		fr->buff[j++] = helper[i];
	}

	free(helper);

	size = MIN(BLOCK_SIZE, j);
	memcpy(buffer, fr->buff, size);
	memmove(fr->buff, fr->buff + BLOCK_SIZE, BLOCK_SIZE);
	fr->offset = j - BLOCK_SIZE;
	return size;
}

// ============================================================================

void SendTFTPpacket(int socket, const struct sockaddr* client,
	u_short opcode, u_short code, const void* ptr, ssize_t size){

	size_t packet_size = 4;

	tftp_packet packet;
	packet.opcode = htons(opcode);
	packet.code   = htons(code);
	if (ptr != NULL){
		memset(packet.block, 0, BLOCK_SIZE);
		memcpy(packet.block, ptr, size);
		packet_size += size;
	}

	Sendto(socket, &packet, packet_size, 0, client, sizeof(struct sockaddr));
}

void Error(int socket, const struct sockaddr* client,
	const char* error_string, u_short error_code){

	SendTFTPpacket(socket, client, TFTP_ERROR, error_code, error_string, strlen(error_string));

	if (is_daemon)
		syslog(LOG_ALERT, "TFTP ERROR %u fh47758 %s", error_code, error_string);
	else
		fprintf(stderr, "TFTP ERROR %u fh47758 %s\n", error_code, error_string);
}

void OutputMessage(const struct sockaddr* client, const char* filename, byte read){
	char* ip = GetIP(client);
	char* arrow = read ? "->" : "<-";

	if (is_daemon)
		syslog(LOG_INFO, "%s%s%s", ip, arrow, filename);
	else
		fprintf(stdout, "%s%s%s\n", ip, arrow, filename);
	free(ip);
}

// ============================================================================

tftp_request* FillRequest(const byte* buffer, ssize_t buffer_len,
	int socket, struct sockaddr* client){

	int i;
	char* transfer_type = MLC(char, BUFFER_LEN);
	u_short err_code = TFTP_ER_NOTDEF;
	tftp_request* req = MLC(tftp_request, 1);

	if (buffer_len < 2){
		Error(socket, client, "Buffer to short", err_code);
		return NULL;
	}

	memcpy(&req->opcode, buffer, sizeof(u_short));
	req->opcode = ntohs(req->opcode);

	if (req->opcode != TFTP_RRQ && req->opcode != TFTP_WRQ){
		printf("%d %d %d\n", req->opcode, TFTP_RRQ, TFTP_WRQ);
		Error(socket, client, "Not RRQ/WRQ", TFTP_ER_ILLEGAL);
		return NULL;
	}

	// skip opcode
	buffer     += 2;
	buffer_len -= 2;

	req->original_filename = MLC(char, BUFFER_LEN);

	for(i=0; i<buffer_len && buffer[i]; i++){
		req->original_filename[i] = (char) buffer[i];
	}

	if (!i){
		Error(socket, client, "Filename not found", err_code);
		return NULL;
	}

	buffer     += i+1;
	buffer_len -= i+1;

	for(i=0; i<buffer_len && buffer[i]; i++){
		transfer_type[i] = tolower(buffer[i]);
	}

	if (!strcmp(transfer_type, "octet"))
		req->binary = 1;
	else if (!strcmp(transfer_type, "netascii"))
		req->binary = 0;
	else {
		Error(socket, client, "Unsupported transfer type", err_code);
		return NULL;
	}

	return req;
}

int NewSocket(){
	int socket;
	struct sockaddr_in server;

	memset(&server, 0, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = htons(0);
	server.sin_addr.s_addr = INADDR_ANY;

	socket = Socket(AF_INET, SOCK_DGRAM, 0);
	Bind(socket, (struct sockaddr*) &server, sizeof(struct sockaddr));

	return socket;
}

void* ReadRQ(void* args){
	tftp_request* req = (tftp_request*) args;
	int socket = NewSocket();

	u_short ack = 0;
	byte* ack_buff = MLC(byte, 4);
	ssize_t ack_buff_len;
	socklen_t addrlen;

	u_short opcode, code;
	u_short retransmitions = NO_RETRANS;


	file_reader* fr = createReader(req->filename, req->binary);
	byte* buffer = MLC(byte, BLOCK_SIZE);
	size_t size;

	SetTimeout(socket, TIMEOUT_SEC, TIMEOUT_MSC);

	do {
		size = readFromReader(fr, buffer);

		SendTFTPpacket(socket, req->addr, TFTP_DATA, ack+1, buffer, size);
		retransmitions = 0;

		do{

			addrlen = sizeof(struct sockaddr);
			ack_buff_len = recvfrom(socket, ack_buff, 4, 0, req->addr, &addrlen);

			if (ack_buff_len < 0){
				if (errno == EWOULDBLOCK){
					retransmitions++;
					SendTFTPpacket(socket, req->addr, TFTP_DATA, ack+1, buffer, size);
					continue;
				} else {
					Warnx("recvfrom %s", strerror(errno));
					continue;
				}
			}

			if (In_port(req->addr) != req->tid){
				Error(socket, req->addr, "Wrong TID", TFTP_ER_PORT);
				continue;
			}

			if (ack_buff_len != 4){
				Error(socket, req->addr, "Not ACK", TFTP_ER_ILLEGAL);
				continue;
			}

			memcpy(&opcode, ack_buff, 2);
			memcpy(&code, ack_buff+2, 2);

			opcode = ntohs(opcode);
			code   = ntohs(code);

			if (opcode != TFTP_ACK){
				Error(socket, req->addr, "Not ACK", TFTP_ER_ILLEGAL);
				continue;
			}

			if (code != ack+1){
				continue;
			} else {
				ack++;
				break;
			}

		} while(retransmitions < NO_RETRANS);

		if (retransmitions == NO_RETRANS){
			Error(socket, req->addr, "Stopped after 3 retransmitions", TFTP_ER_NOTDEF);
			break;
		}

	} while( size == BLOCK_SIZE );

	if (size != BLOCK_SIZE && retransmitions != NO_RETRANS)
		OutputMessage(req->addr, req->original_filename, 0);

	destroyReader(fr);
	free(buffer);
	free(ack_buff);
	free(req);
	Close(socket);
	pthread_exit(0);
}

byte writeToFile(FILE* file, byte* buffer, size_t size, byte binary, byte was_r){
	byte* helper;
	int i,j;
	byte r = 0;
	if (!binary){
		helper = MLC(byte, size);
		i=0,j=0;
		if (was_r){
			j=1;
			if (buffer[0] == '\n'){
				i=1;
				helper[0] = '\n';
			} else{
				helper[0] = '\r';
			}
		}
		for(; i<size; i++){
			if (buffer[i]=='\r'){
				if (i+1 == size)
					r = 1;
				else if (buffer[i+1]=='\n'){
					helper[j++] = '\n';
					i++;
				}
			} else{
				helper[j++] = buffer[i];
			}
		}
		buffer = helper;
		size   = j;
	}
	fwrite(buffer, sizeof(byte), size, file);
	return r;
}

void* WriteRQ(void* args){
	tftp_request* req = (tftp_request*) args;
	int socket = NewSocket();

	FILE* file = fopen(req->filename, "wb");

	tftp_packet packet;
	ssize_t packet_len;
	u_short block = 0;
	byte was_r = 0;
	byte retransmitions;
	socklen_t addrlen;

	SetTimeout(socket, TIMEOUT_SEC, TIMEOUT_MSC); // mozda

	do {

		SendTFTPpacket(socket, req->addr, TFTP_ACK, block, NULL, 0);
		retransmitions = 0;

		do{

			addrlen = sizeof(struct sockaddr);
			packet_len = recvfrom(socket, &packet, sizeof(packet), 0, req->addr, &addrlen);

			if (packet_len < 0){
				if (errno == EWOULDBLOCK){
					retransmitions++;
					SendTFTPpacket(socket, req->addr, TFTP_ACK, block, NULL, 0);
					continue;
				} else {
					Warnx("recvfrom %s", strerror(errno));
					continue;
				}
			}

			if (In_port(req->addr) != req->tid){
				Error(socket, req->addr, "Wrong TID", TFTP_ER_PORT);
				continue;
			}

			if (packet_len < 4){
				Error(socket, req->addr, "Package too small", TFTP_ER_ILLEGAL);
				continue;
			}

			packet.opcode = ntohs(packet.opcode);
			packet.code   = ntohs(packet.code);

			if (packet.opcode != TFTP_DATA){
				Error(socket, req->addr, "Not DATA", TFTP_ER_ILLEGAL);
				continue;
			}

			if (packet.code != block+1){
				continue;
			} else {
				block++;
				was_r = writeToFile(file, packet.block, packet_len - 4, req->binary, was_r);
				SendTFTPpacket(socket, req->addr, TFTP_ACK, block, NULL, 0);
				break;
			}

		} while(retransmitions < NO_RETRANS);

		if (retransmitions == NO_RETRANS){
			Error(socket, req->addr, "Stopped after 3 retransmitions", TFTP_ER_NOTDEF);
			break;
		}

	} while( packet_len == BLOCK_SIZE+4 );

	if (packet_len != BLOCK_SIZE + 4 && retransmitions != NO_RETRANS)
		OutputMessage(req->addr, req->original_filename, 0);

	fclose(file);
	free(req);
	Close(socket);
	pthread_exit(0);
}

int main(int argc, char** argv){

	char ch;
	byte create_daemon = 0;

    int socket;
	byte* buffer = MLC(byte, BUFFER_LEN);
	ssize_t buffer_len;
	tftp_request* req;

	pthread_t tid;
	int dir_len = strlen(ROOT_DIR);
	int i;

	struct sockaddr client;
    socklen_t client_len;

    while ( (ch=getopt(argc, argv, "d")) != -1 ){
        if (ch == 'd') create_daemon = 1;
        else Usage(argv[0]);
    }
    if (argc - optind != 1) Usage(argv[0]);

	socket = UDPserver(argv[optind]);

	if (create_daemon){
		Daemon(1, 0);
		openlog(LOG_NAME, LOG_PID, LOG_FTP);
	}

	chdir(ROOT_DIR);

    while( 1 ){
		memset(buffer, 0, BUFFER_LEN);
        client_len = sizeof(struct sockaddr);

		buffer_len = Recvfrom(socket, buffer, BUFFER_LEN, 0,
		 &client, &client_len);

		req = FillRequest(buffer, buffer_len, socket, &client);
		if (req == NULL) continue;

		req->addr = MLC(struct sockaddr, 1);
		memcpy(req->addr, &client, sizeof(client));
		req->tid = In_port(&client);


		// remove prefix
		req->filename = req->original_filename;
		if (strlen(req->filename) > dir_len
			&& !strncmp(req->filename, ROOT_DIR, dir_len))
			req->filename += dir_len;
		if (req->filename[0] == '/') req->filename++;
		// check filename
		for(i=strlen(req->filename)-1; i>=0; i--){
			if (req->filename[i] == '/') break;
		}
		if (i!=-1){
			Error(socket, &client, "Filename contains /", TFTP_ER_ACCESS);
			continue;
		}

		if (req->opcode == TFTP_RRQ){
			if (access(req->filename, F_OK)){
				Error(socket, &client, "File doesn't exist", TFTP_ER_EXISTS);
				continue;
			}
			if (access(req->filename, R_OK)){
				Error(socket, &client, "Access denied", TFTP_ER_ACCESS);
				continue;
			}
		}

		if (req->opcode == TFTP_RRQ)
			pthread_create(&tid, NULL, ReadRQ,  (void*) req);
		else
			pthread_create(&tid, NULL, WriteRQ, (void*) req);
    }

    Close(socket);
    return 0;
}
