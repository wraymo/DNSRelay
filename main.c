#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <WS2tcpip.h>
#include <time.h>

#define MAX_ADDLENGTH 16
#define MAX_PATHLENGTH 100
#define MAX_BUFFERSIZE 1024
#define MAX_TABLEENTRY 1000
#define MAX_RECORD 400
#define DEFAULT_DNS "10.3.9.5"

typedef unsigned __int64 uint64_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;

int verbose;
int optind = 1;
char* optarg;
int count;

FILE* cache;
uint8_t* buffer;
SOCKET hostSocket;
SOCKADDR_IN hostAddr;
SOCKADDR_IN from;
SOCKADDR_IN serverAddr;

//                                    1  1  1  1  1  1
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      ID                       |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    QDCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    ANCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    NSCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    ARCOUNT                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
typedef struct DNSHeader 
{
	uint16_t ID;
	uint16_t QR : 1;
	uint16_t Opcode : 4;
	uint16_t AA : 1;
	uint16_t TC : 1;
	uint16_t RD : 1;
	uint16_t RA : 1;
	uint16_t Z : 3;
	uint16_t RCODE : 4;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;
} DNSHeader;

//                                    1  1  1  1  1  1
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                     QNAME                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QTYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QCLASS                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
typedef struct Question {
	uint8_t* QNAME;
	uint16_t QTYPE;
	uint16_t QCLASS;
} Question;

//                                    1  1  1  1  1  1
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                                               /
//    /                      NAME                     /
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     CLASS                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TTL                      |
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   RDLENGTH                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//    /                     RDATA                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
typedef struct ResourceRecord {
	char* NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	uint8_t* RDATA;
} ResourceRecord;

/*  +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+  */
struct Message {
	DNSHeader dnsheader;
	Question* question;
	ResourceRecord* answer;
	ResourceRecord* authority;
	ResourceRecord* additional;
	SOCKADDR_IN senderAddr;
} message;

typedef struct Entry {
	char IP[16];      
	char* name;
} Entry;

struct NameTable{
	Entry nametable[MAX_TABLEENTRY];
	int size;
} nameTable;

typedef struct Record{
	SOCKADDR_IN senderAddr;
	uint16_t ID;
	char* name;
} Record;

struct RecordTable {
	Record recordtable[MAX_RECORD];
	int size;
} recordTable;

int getopt(int argc, char** argv)
{
	if (optind >= argc) {
		return -1;
	}
	if (!strcmp(argv[optind], "-d")) {
		optind++;
		return 'd';
	}
	if (!strcmp(argv[optind], "-dd")) {
		optind++;
		return 'e';
	}
	if (!strcmp(argv[optind], "-i")) {
		optind++;
		if (optind >= argc)
			return 'w';
		else {
			optarg = argv[optind++];
			return 'i';
		}
	}
	if (!strcmp(argv[optind], "-s")) {
		optind++;
		if (optind >= argc)
			return 'w';
		else {
			optarg = argv[optind++];
			return 's';
		}
	}
	return 'w';
}

char* mkcopy(const char* src)
{
	int len = strlen(src);
	char* ret = (char*)malloc(len + 1);
	strcpy(ret, src);
	return ret;
}

void init(const char *path)
{
	char tempIP[MAX_ADDLENGTH + 1];
	char tempName[100];
	int c;
	
	if (path[0])
		cache = fopen("path", "r+");
	else
		cache = fopen("dnsrelay.txt", "r+");
	if (!cache) {
		printf("Cannot open the file\n");
		exit(1);
	}

	while (!feof(cache)) {
		while ((c = getc(cache)) == '\n' || c == '\t' || c == ' ');
		if (feof(cache))
			break;
		ungetc(c, cache);
		fscanf(cache, "%s %s\n", tempIP, tempName);
		strncpy(nameTable.nametable[nameTable.size].IP, tempIP, MAX_ADDLENGTH);
		nameTable.nametable[nameTable.size++].name = mkcopy(tempName);
	}

	nameTable.size = 0;
	recordTable.size = 0;

	hostSocket = socket(AF_INET, SOCK_DGRAM, 0);
	hostAddr.sin_family = AF_INET;
	hostAddr.sin_port = htons(53);
	hostAddr.sin_addr.S_un.S_addr = INADDR_ANY;

	if (bind(hostSocket, (SOCKADDR*)& hostAddr, sizeof(SOCKADDR_IN)) < 0) {
		printf("Failed to bind socket to sockaddr.\n");
		exit(1);
	}

	buffer = (uint8_t*)malloc(MAX_BUFFERSIZE);

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(53);
	inet_pton(AF_INET, DEFAULT_DNS, (void*) & (serverAddr.sin_addr));
}

void freeSpace()
{
	int i;
	if (message.question) {
		for (i = 0; i < message.dnsheader.QDCOUNT; i++) {
			if (message.question[i].QNAME)
				free(message.question[i].QNAME);
		}
		free(message.question);
	}

	if (message.answer){
		for (i = 0; i < message.dnsheader.ANCOUNT; i++) {
			if (message.answer[i].NAME)
				free(message.answer[i].NAME);
			if(message.answer[i].RDATA)
				free(message.answer[i].RDATA);
		}
		free(message.answer);
	}
	
	if (message.authority) {
		for (i = 0; i < message.dnsheader.NSCOUNT; i++) {
			if (message.authority[i].NAME)
				free(message.authority[i].NAME);
			if (message.authority[i].RDATA)
				free(message.authority[i].RDATA);
		}
		free(message.authority);
	}

	if (message.additional) {
		for (i = 0; i < message.dnsheader.ARCOUNT; i++) {
			if (message.additional[i].NAME)
				free(message.additional[i].NAME);
			if (message.additional[i].RDATA)
				free(message.additional[i].RDATA);
		}
		free(message.additional);
	}
}

void ExtractHeader(uint8_t** ptr)
{
	uint16_t temp;
	message.dnsheader.ID = ntohs(*(uint16_t*)(*ptr));
	*ptr += 2;
	temp = ntohs(*(uint16_t*)(*ptr));
	message.dnsheader.QR = (temp & 0x8000) >> 15;
	message.dnsheader.Opcode = (temp & 0x7800) >> 11;
	message.dnsheader.AA = (temp & 0x0400) >> 10;
	message.dnsheader.TC = (temp & 0x0200) >> 9;
	message.dnsheader.RD = (temp & 0x0100) >> 8;
	message.dnsheader.RA = (temp & 0x0080) >> 7;
	message.dnsheader.Z = (temp & 0x0070) >> 4;
	message.dnsheader.RCODE = temp & 0x000f;
	*ptr += 2;
	message.dnsheader.QDCOUNT = ntohs(*(uint16_t*)(*ptr));
	*ptr += 2;
	message.dnsheader.ANCOUNT = ntohs(*(uint16_t*)(*ptr));
	*ptr += 2;
	message.dnsheader.NSCOUNT = ntohs(*(uint16_t*)(*ptr));
	*ptr += 2;
	message.dnsheader.ARCOUNT = ntohs(*(uint16_t*)(*ptr));
	*ptr += 2;
}

void extractName(uint8_t** ptr, char** name)
{
	while (**ptr != 0) {
		if ((**ptr & 0xc0) == 0xc0) {
			uint16_t offset = ntohs(*(uint16_t*)(*ptr));
			*ptr += 2;
			uint8_t* next = buffer + (offset & 0x3fff);
			extractName(&next, name);
			return;
		}
		else {
			uint8_t len = **ptr;
			int oldlen = strlen(*name);
			*name = realloc(*name, oldlen + (uint64_t)len + 2);
			memcpy(*name + oldlen, *ptr, (uint64_t)len + 1);
			*ptr += (uint64_t)len + 1;
			*(*name + oldlen + (uint64_t)len + 1) = '\0';
		}
	}
	(*ptr)++;
}

void ExtractQuestion(uint8_t** ptr)
{
	int i;
	char* name;
	uint16_t qcount = message.dnsheader.QDCOUNT;
	message.question = (Question*)malloc(sizeof(Question) * qcount);
	for (i = 0; i < qcount; i++) {
		name = mkcopy("");
		extractName(ptr, &name);
		message.question[i].QNAME = mkcopy(name);
		message.question[i].QTYPE = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.question[i].QCLASS = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		free(name);
	}
}

void ExtractRR(uint8_t** ptr)
{
	int i;
	uint16_t rrcount;
	char* name;

	rrcount = message.dnsheader.ANCOUNT;
	message.answer = (ResourceRecord*)malloc(sizeof(ResourceRecord) * rrcount);
	for (i = 0; i < rrcount; i++) {
		name = mkcopy("");
		extractName(ptr, &name);
		message.answer[i].NAME = mkcopy(name);
		message.answer[i].TYPE = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.answer[i].CLASS = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.answer[i].TTL = ntohs(*(uint32_t*)(*ptr));
		*ptr += 4;
		message.answer[i].RDLENGTH = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.answer[i].RDATA = (uint8_t)malloc(message.answer[i].RDLENGTH);
		memcpy(message.answer[i].RDATA, *ptr, message.answer[i].RDLENGTH);
		*ptr += message.answer[i].RDLENGTH;
		free(name);
	}

	rrcount = message.dnsheader.NSCOUNT; 
	message.authority = (ResourceRecord*)malloc(sizeof(ResourceRecord) * rrcount);
	for (i = 0; i < rrcount; i++) {
		name = mkcopy("");
		extractName(ptr, &name);
		message.authority[i].NAME = mkcopy(name);
		message.authority[i].TYPE = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.authority[i].CLASS = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.authority[i].TTL = ntohs(*(uint32_t*)(*ptr));
		*ptr += 4;
		message.authority[i].RDLENGTH = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.authority[i].RDATA = (uint8_t)malloc(message.authority[i].RDLENGTH);
		memcpy(message.authority[i].RDATA, *ptr, message.authority[i].RDLENGTH);
		*ptr += message.authority[i].RDLENGTH;
		free(name);
	}

	rrcount = message.dnsheader.ARCOUNT; 
	message.additional = (ResourceRecord*)malloc(sizeof(ResourceRecord) * rrcount);
	for (i = 0; i < rrcount; i++) {
		name = mkcopy("");
		extractName(ptr, &name);
		message.additional[i].NAME = mkcopy(name);
		message.additional[i].TYPE = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.additional[i].CLASS = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.additional[i].TTL = ntohs(*(uint32_t*)(*ptr));
		*ptr += 4;
		message.additional[i].RDLENGTH = ntohs(*(uint16_t*)(*ptr));
		*ptr += 2;
		message.additional[i].RDATA = (uint8_t)malloc(message.additional[i].RDLENGTH);
		memcpy(message.additional[i].RDATA, *ptr, message.additional[i].RDLENGTH);
		*ptr += message.additional[i].RDLENGTH;
		free(name);
	}
}

void ExtractMessage()
{
	uint8_t* ptr = buffer;
	ExtractHeader(&ptr);
	ExtractQuestion(&ptr);
	ExtractRR(&ptr);
	message.senderAddr = from;
}

void printName(uint8_t *name)
{
    int cnt = 0, i;
	int length = strlen(name);
    for (i = 0; i < length; i++) {
        if (!cnt) {
            cnt = name[i];
            printf("%d", name[i]);
        }
        else {
            cnt--;
            printf("%c", name[i]);
        }
    }
	putchar('\n');
}

void printMessage(time_t *time)
{
	int i;
	switch (verbose)
	{
	case 0: break;
	case 1: 
		printf("Time: %s\n", ctime(time));
		printf("Count: %d\n", count);
		printf("Name: ");
		printName(message.question[i].QNAME);
		break;
	case 2:
		printf("Time: %s\n", ctime(time));
		printf("Count: %d\n", count);
		printf("------------------HEADER------------------\n");
		printf("ID:      %X\n",message.dnsheader.ID);
		printf("QR:      %X\n", message.dnsheader.QR);
		printf("Opcode:  %X\n", message.dnsheader.Opcode);
		printf("AA:      %X\n", message.dnsheader.AA);
		printf("TC:      %X\n", message.dnsheader.TC);
		printf("RD:      %X\n", message.dnsheader.RD);
		printf("RA:      %X\n", message.dnsheader.RA);
		printf("Z:       %X\n", message.dnsheader.Z);
		printf("RCODE:   %X\n", message.dnsheader.RCODE);
		printf("QDCOUNT: %d\n", message.dnsheader.QDCOUNT);
		printf("ANCOUNT: %d\n", message.dnsheader.ANCOUNT);
		printf("NSCOUNT: %d\n", message.dnsheader.NSCOUNT);
		printf("ARCOUNT: %d\n", message.dnsheader.ARCOUNT);

		printf("------------------QUESTION------------------\n");
		for (i = 0; i < message.dnsheader.QDCOUNT; i++) {
			printf("Question: %d\n", i + 1);
			printf("QNAME:  ");
			printName(message.question[i].QNAME);
			printf("QTYPE:  %X\n", message.question[i].QTYPE);
			printf("QCLASS: %X\n", message.question[i].QCLASS);
		}

		printf("------------------ANSWER------------------\n");
		for (i = 0; i < message.dnsheader.ANCOUNT; i++) {
			printf("Answer: %d\n", i + 1);
			printf("NAME:     ");
			printName(message.answer[i].NAME);
			printf("TYPE:     %X\n", message.answer[i].TYPE);
			printf("CLASS:    %X\n", message.answer[i].CLASS);
			printf("TTL:      %X\n", message.answer[i].TTL);
			printf("RDLENGTH: %d\n", message.answer[i].RDLENGTH);
			printf("RDATA: \n");
			int j;
			for (j = 0; j < message.answer[i].RDLENGTH; j++) {
				printf("%X  ", message.answer[i].RDATA[j]);
				if (j == message.answer[i].RDLENGTH-1) {
					putchar('\n');
				}
			}
		}

		printf("------------------AUTHORITY------------------\n");
		for (i = 0; i < message.dnsheader.NSCOUNT; i++) {
			printf("Authority: %d\n", i + 1);
			printf("NAME:     ");
			printName(message.authority[i].NAME);
			printf("TYPE:     %X\n", message.authority[i].TYPE);
			printf("CLASS:    %X\n", message.authority[i].CLASS);
			printf("TTL:      %X\n", message.authority[i].TTL);
			printf("RDLENGTH: %d\n", message.authority[i].RDLENGTH);
			printf("RDATA: \n");
			int j;
			for (j = 0; j < message.authority[i].RDLENGTH; j++) {
				printf("%X  ", message.authority[i].RDATA[j]);
				if (j == message.authority[i].RDLENGTH - 1) {
					putchar('\n');
				}
			}
		}

		printf("------------------ADDITIONAL------------------\n");
		for (i = 0; i < message.dnsheader.ARCOUNT; i++) {
			printf("Additional: %d\n", i + 1);
			printf("NAME:     ");
			printName(message.additional[i].NAME);
			printf("TYPE:     %X\n", message.additional[i].TYPE);
			printf("CLASS:    %X\n", message.additional[i].CLASS);
			printf("TTL:      %X\n", message.additional[i].TTL);
			printf("RDLENGTH: %d\n", message.additional[i].RDLENGTH);
			printf("RDATA: \n");
			int j;
			for (j = 0; j < message.additional[i].RDLENGTH; j++) {
				printf("%X  ", message.additional[i].RDATA[j]);
				if (j == message.additional[i].RDLENGTH - 1) {
					putchar('\n');
				}
			}
		}
		break;
	}
}

char* transName(uint8_t* name)
{
	char* ret = (char*)malloc(strlen(name) + 1);
	int i, k = 0;
	for (i = 0; name[i]; i++) {
		int size = name[i];
		int temp = size;
		while (temp--)
			ret[k++] = name[++i];
		if(size)
			ret[k++] = '.';
	}
	ret[k] = '\0';
	return ret;
}

int findTable(char* name)
{
	int i, size = nameTable.size;
	for (i = 0; i < size; i++)
		if (!strcmp(name, nameTable.nametable[i].IP))
			return i;
	return -1;
}

void createAnswer(char* IP, char* name)
{
	if (!strcmp(IP, "0.0.0.0")) {
		message.dnsheader.QR = 1;
		message.dnsheader.RCODE = 3;
	}
	else {
		message.dnsheader.QR = 1;
		message.dnsheader.AA = 1;
		message.dnsheader.RA = 1;
		message.dnsheader.RCODE = 0;
		message.dnsheader.ANCOUNT = 1;
		if (!message.answer)
			message.answer = (ResourceRecord*)malloc(sizeof(ResourceRecord));
		if (!message.answer[0].NAME)
			message.answer[0].NAME = mkcopy(name);
		else {
			message.answer[0].NAME = realloc(message.answer[0].NAME, strlen(name) + 1);
			strcpy(message.answer[0].NAME, name);
		}
		message.answer[0].TYPE = 1;
		message.answer[0].CLASS = 1;
		message.answer[0].RDLENGTH = 4;
		IN_ADDR tmpAddr;
		inet_pton(AF_INET, IP, (void*)& tmpAddr);
		int tmp = tmpAddr.S_un.S_addr;
		if (!message.answer[0].RDATA)
			message.answer[0].RDATA = (uint8_t*)malloc(4);
		memcpy(message.answer[0].RDATA, &tmp, 4);
		message.answer[0].TTL = 86400;
	}
}

void put16bits(uint16_t value, uint8_t** ptr, int* buffersize)
{
	*(uint16_t*)(*ptr) = (uint16_t)htons(value);
	*ptr += sizeof(uint16_t);
	*buffersize += sizeof(uint16_t);
}

void put32bits(uint16_t value, uint8_t** ptr, int* buffersize)
{
	*(uint32_t*)(*ptr) = (uint32_t)htons(value);
	*ptr += sizeof(uint32_t);
	*buffersize += sizeof(uint32_t);
}

void constructHeader(uint8_t** ptr, int* buffersize)
{
	uint16_t temp = 0;
	temp |= message.dnsheader.QR << 15;
	temp |= message.dnsheader.Opcode << 11;
	temp |= message.dnsheader.AA << 10;
	temp |= message.dnsheader.TC << 9;
	temp |= message.dnsheader.RD << 8;
	temp |= message.dnsheader.RA << 7;
	temp |= message.dnsheader.Z << 4;
	temp |= message.dnsheader.RCODE;

	put16bits(message.dnsheader.ID, ptr, buffersize);
	put16bits(temp, ptr, buffersize);
	put16bits(message.dnsheader.QDCOUNT, ptr, buffersize);
	put16bits(message.dnsheader.ANCOUNT, ptr, buffersize);
	put16bits(message.dnsheader.NSCOUNT, ptr, buffersize);
	put16bits(message.dnsheader.ARCOUNT, ptr, buffersize);
}

void constructQuestion(uint8_t** ptr, int* buffersize)
{
	int i;
	for (i = 0; i < message.dnsheader.QDCOUNT; i++) {
		memcpy(*ptr, message.question[i].QNAME, strlen(message.question[i].QNAME));
		*buffersize += strlen(message.question[i].QNAME);
		*ptr += strlen(message.question[i].QNAME);
		put16bits(message.question[i].QTYPE, ptr, buffersize);
		put16bits(message.question[i].QCLASS, ptr, buffersize);
	}
}

void constructRR(uint8_t** ptr, int* buffersize)
{
	int i;
	for (i = 0; i < message.dnsheader.ANCOUNT; i++) {
		memcpy(*ptr, message.answer[i].NAME, strlen(message.answer[i].NAME));
		*buffersize += strlen(message.answer[i].NAME);
		*ptr += strlen(message.answer[i].NAME);

		put16bits(message.answer[i].TYPE, ptr, buffersize);
		put16bits(message.answer[i].CLASS, ptr, buffersize);
		put32bits(message.answer[i].TTL, ptr, buffersize);
		put16bits(message.answer[i].RDLENGTH, ptr, buffersize);

		memcpy(*ptr, message.answer[i].RDATA, message.answer[i].RDLENGTH);
		*buffersize += message.answer[i].RDLENGTH;
		*ptr += message.answer[i].RDLENGTH;
	}

	for (i = 0; i < message.dnsheader.NSCOUNT; i++) {
		memcpy(*ptr, message.authority[i].NAME, strlen(message.authority[i].NAME));
		*buffersize += strlen(message.authority[i].NAME);
		*ptr += strlen(message.authority[i].NAME);

		put16bits(message.authority[i].TYPE, ptr, buffersize);
		put16bits(message.authority[i].CLASS, ptr, buffersize);
		put32bits(message.authority[i].TTL, ptr, buffersize);
		put16bits(message.authority[i].RDLENGTH, ptr, buffersize);

		memcpy(*ptr, message.authority[i].RDATA, message.authority[i].RDLENGTH);
		*buffersize += message.authority[i].RDLENGTH;
		*ptr += message.authority[i].RDLENGTH;
	}

	for (i = 0; i < message.dnsheader.ARCOUNT; i++) {
		memcpy(*ptr, message.additional[i].NAME, strlen(message.additional[i].NAME));
		*buffersize += strlen(message.additional[i].NAME);
		*ptr += strlen(message.additional[i].NAME);

		put16bits(message.additional[i].TYPE, ptr, buffersize);
		put16bits(message.additional[i].CLASS, ptr, buffersize);
		put32bits(message.additional[i].TTL, ptr, buffersize);
		put16bits(message.additional[i].RDLENGTH, ptr, buffersize);

		memcpy(*ptr, message.additional[i].RDATA, message.additional[i].RDLENGTH);
		*buffersize += message.additional[i].RDLENGTH;
		*ptr += message.additional[i].RDLENGTH;
	}
}

int constructMessage(char* IP, char* name)
{
	createAnswer(IP, name);
	memset(buffer, 0, MAX_BUFFERSIZE);
	uint8_t* ptr = buffer;
	int buffersize = 0;
	constructHeader(&ptr, &buffersize);
	constructQuestion(&ptr, &buffersize);
	constructRR(&ptr, &buffersize);
	return buffersize;
}

void insertRecord()
{
	recordTable.recordtable[recordTable.size].ID = message.dnsheader.ID;
	recordTable.recordtable[recordTable.size].senderAddr = message.senderAddr;
	recordTable.recordtable[recordTable.size].name = mkcopy(message.question[0].QNAME);
}

void insertEntry(uint32_t IP, char* name)
{
	fseek(cache, 0, SEEK_END);
	IN_ADDR temp;
	temp.S_un.S_addr = IP;
	nameTable.nametable[nameTable.size].name = mkcopy(name);
	inet_ntop(AF_INET, &temp, nameTable.nametable[nameTable.size].IP, MAX_ADDLENGTH);
	fprintf(cache, "%s %s\n", nameTable.nametable[nameTable.size++].IP, name);
}

int findRecord(uint16_t ID, SOCKADDR_IN* temp, char** name)
{
	int i, size = recordTable.size;
	for (i = 0; i < size; i++)
		if (recordTable.recordtable[i].ID == ID) {
			*temp = recordTable.recordtable[i].senderAddr;
			*name = recordTable.recordtable[i].name;
			return 1;
		}
	return 0;
}

void sendToServer(int bytes)
{
	insertRecord();
	sendto(hostSocket, buffer, bytes, 0, &serverAddr, sizeof(serverAddr));
}

void sendAnswer(int recvbytes)
{
	time_t t;
	time(&t);
	if (message.dnsheader.QDCOUNT == 1 &&
		message.question[0].QTYPE == 1 && message.question[0].QCLASS == 1) {
		char* name = transName(message.question[0].QNAME);
		int index = findTable(name);
		if (index >= 0) {
			int buffersize = constructMessage(nameTable.nametable[index].IP, message.question[0].QNAME); 
			printf("find the record in local name table\n");
			printf("the message is sent to the server\n");
			printMessage(&t);
			if(sendto(hostSocket, buffer, buffersize, 0, &message.senderAddr, sizeof(message.senderAddr)) < 0)
				printf("fail to send response\n");
		}
		else {
			printf("fail to find the record in local name table\n");
			sendToServer(recvbytes);
		}
		free(name);
	}
	else {
		printf("cannot handle this message\n");
		sendToServer(recvbytes);
	}
}

void analyzeResponse(int bytes)
{
	SOCKADDR_IN tempAddr;
	char* name;
	if (findRecord(message.dnsheader.ID, &tempAddr, &name))
	{
		int i;
		for (i = 0; i < message.dnsheader.QDCOUNT; i++) {
			if (message.answer[i].TYPE == 1 && message.answer[i].CLASS == 1) {
				uint32_t IP = *(uint32_t*)message.answer[i].RDATA;
				insertEntry(IP, name);
				break;
			}
		}
		if (sendto(hostSocket, buffer, bytes, 0, &tempAddr, sizeof(tempAddr)) < 0)
			printf("fail to send the response.");
	}
}

void recvMessage()
{
	time_t t;
	int fromlen = sizeof(SOCKADDR_IN);
	int recv = recvfrom(hostSocket, buffer, sizeof(buffer), 0, (SOCKADDR*)& from, &fromlen);
	if (recv <= 0)
		printf("Failed to connect.\n");
	count++;
	time(&t);

	printf("%s\n",ctime(&t));
	freeSpace();
	ExtractMessage();

	if (message.dnsheader.QR == 0 && message.dnsheader.Opcode == 0) {
		printf("recieve a request from a server\n");
		printMessage(&t);
		sendAnswer(recv);
	}

	else if (message.dnsheader.QR == 1) {
		printf("recieve a response from a server\n");
		printMessage(&t);
		analyzeResponse(recv);
	}

	else {
		printf("receive other message from a server\n");
		printMessage(&t);
		sendToServer(recv);
	}
}

int main(int argc, char** argv)
{
	DNSHeader a;
	return 0;
	int ret;
	char server[MAX_ADDLENGTH + 1] = {'\0'};
	char path[MAX_PATHLENGTH + 1] = {'\0'};

	while ((ret = getopt(argc, argv)) != -1){
		switch (ret){
		case 'd': verbose = 1; break;
		case 'e': verbose = 2; break;
		case 's': strncpy(server, optarg, MAX_ADDLENGTH); break;
		case 'i': strncpy(path, optarg, MAX_PATHLENGTH); break;
		case 'w': printf("Wrong command\n"); exit(1); break;
		}
	}

	init(path);
	
	while (1){
		recvMessage();
	}
}
