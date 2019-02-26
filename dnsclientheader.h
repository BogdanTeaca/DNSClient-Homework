// TEACA BOGDAN

#define	A     1
#define	NS    2
#define	CNAME 5
#define	MX    15
#define SOA   6
#define	TXT   16
#define PTR   12

typedef struct{
	unsigned short id;

	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1;
	
	unsigned char rcode :4;
	unsigned char z :3;
	unsigned char ra :1;

	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} dns_header_t;

typedef struct{
	// qname variabil
	unsigned short qtype;
	unsigned short qclass;
} dns_question_t;

typedef struct{
	// name variabil
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
	// rdata variabil
} dns_rr_t;