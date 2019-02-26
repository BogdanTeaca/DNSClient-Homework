// TEACA BOGDAN

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

#include "dnsclientheader.h"

#define DNS_LOG_FILENAME "dns.log"
#define MESSAGE_LOG_FILENAME "message.log"
#define SERVERS_CONF_FILENAME "dns_servers.conf"

#define BUFLEN 1024

#define TRUE 1
#define FALSE 0

#define TIMEOUT_SECONDS 5

// functie care converteste un string din formatul text (human readable) in formatul DNS
void convertTextToDnsFormat(char * textFormat, char * dnsFormat){
	int n = strlen(textFormat);

	memset(dnsFormat, 0, n);

	int current = 0;

	int i;
	for(i = 0; i < n; i++){
		if(textFormat[i] == '.') {
			dnsFormat[current] = i - current;

			strncpy(dnsFormat + current + 1, textFormat + current, dnsFormat[current]);

			current = i + 1;
		}

		if(i == n - 1){
			dnsFormat[current] = n - current;

			strncpy(dnsFormat + current + 1, textFormat + current, dnsFormat[current]);

			break;
		}
	}
	
	dnsFormat[n + 2] = '\0';
}

// functie care converteste un string din formatul DNS intr-un format text (human readable/pentru scriere in fisier)
unsigned char * convertDnsToTextFormat(unsigned char * dnsFormat, char * buffer, int * length){
	unsigned char * textFormat = (unsigned char *)malloc(256 * sizeof(unsigned char));
	int i = 0, skip = FALSE, offset;
	
	(*length) = 1;

	while(*dnsFormat != 0){
		if(*dnsFormat >= 192){
			// calculul de mai jos este echivalent cu "offset = dnsFormat[0] * (2^8) + dnsFormat[1] - ((2^16 - 1) - (2^14 - 1))"
			offset = dnsFormat[0] * 256 + dnsFormat[1] - 49152;
			dnsFormat = buffer + offset - 1;

			skip = 1;
		}else{
			textFormat[i] = *dnsFormat;

			i++;
		}
		
		dnsFormat++;

		if(skip == 0){
			(*length)++;
		}
	}
	
	if(skip == 1){
		(*length)++;
	}
	
	textFormat[i] = '\0';

	int n = strlen(textFormat);
	
	for(i = 0; i < n; i++){
		int size = textFormat[i];

		int j;
		for(j = 0; j < size; j++){
			textFormat[i] = textFormat[i + 1];
			i++;
		}

		textFormat[i] = '.';
	}

	textFormat[i] = '\0';
	
	return textFormat;
}

// functie care interpreteaza mesajul primit de la serverul DNS in functie
// de tipul de query si scrie informatia in fisierul dns.log in formatul
// cerut in enunt
void writeInDNSLog(char * buffer, char ** fromServer){
	FILE * dnsLogFile = fopen(DNS_LOG_FILENAME, "a");

	int position = 0;
	char * name = convertDnsToTextFormat((*fromServer), buffer, &position);
	
	(*fromServer) += position;
					
	dns_rr_t * answer = (dns_rr_t *)(*fromServer);
	(*fromServer) += sizeof(dns_rr_t);

	fprintf(dnsLogFile, "%s %s ", name, (ntohs(answer->class) == 1) ? "IN" : "");

	switch(ntohs(answer->type)){
		case NS:
			fprintf(dnsLogFile, "NS ");
			break;
		case A:
			fprintf(dnsLogFile, "A ");
			break;
		case MX:
			fprintf(dnsLogFile, "MX ");
			break;
		case CNAME:
			fprintf(dnsLogFile, "CNAME ");
			break;
		case SOA:
			fprintf(dnsLogFile, "SOA ");
			break;
		case TXT:
			fprintf(dnsLogFile, "TXT ");
			break;
		case PTR:
			fprintf(dnsLogFile, "PTR ");
			break;
		default:
			break;
	}

	(*fromServer) -= position;

	char * textA;
	char * textB;
	int intA;
	unsigned short i;
	unsigned short len = ntohs(answer->rdlength);
	int offset;

	switch(ntohs(answer->type)){
		// prelucram mesajul primit de tipul authoritative name server si il scriem
		// in fisierul dns.log in formatul din cerinta
		case NS:
			textA = convertDnsToTextFormat((*fromServer), buffer, &offset); // NameServer
			
			fprintf(dnsLogFile, "%s", textA);

			(*fromServer) += offset;

			break;

		// prelucram mesajul primit de tipul adresa IPv4 si il scriem
		// in fisierul dns.log in formatul din cerinta
		case A:
			for(i = 0; i < len; i++){ // Addr
				if((*fromServer)[i] < 0) {
					fprintf(dnsLogFile, "%d", (*fromServer)[i] + 256);
				} else {
					fprintf(dnsLogFile, "%d", (*fromServer)[i]);
				}
				if(i < len - 1) {
					fprintf(dnsLogFile, ".");
				}
			}

			(*fromServer) += 2 * position;

			break;

		// prelucram mesajul primit de tipul mail exchange si il scriem
		// in fisierul dns.log in formatul din cerinta
		case MX:
			intA = (*fromServer)[1]; // Preference
							
			textA = convertDnsToTextFormat(&(*fromServer)[2], buffer, &offset); // MailExchange

			fprintf(dnsLogFile, "%d %s", intA, textA);

			(*fromServer) += offset + 2;

			break;

		// prelucram mesajul primit de tipul canonical name for an alias si il scriem
		// in fisierul dns.log in formatul din cerinta
		case CNAME:	
			textA = convertDnsToTextFormat((*fromServer), buffer, &offset); // PrimaryName
			
			fprintf(dnsLogFile, "%s", textA);

			(*fromServer) += offset;

			break;

		// prelucram mesajul primit de tipul start of a zone of authority si il scriem
		// in fisierul dns.log in formatul din cerinta
		case SOA:
			textA = convertDnsToTextFormat((*fromServer), buffer, &offset);	 // PriName		
			(*fromServer) += offset;
			
			textB = convertDnsToTextFormat((*fromServer), buffer, &offset); // AuthoMailBox
			(*fromServer) += offset;

			unsigned int serial = 0, refresh = 0, retry = 0, expiration = 0, minimum = 0;

			for(i = 0 ; i < 4; i++) {
				serial = serial * 256 + (unsigned char)(*fromServer)[i]; // Serial
				refresh = refresh * 256 + (unsigned char)(*fromServer)[i + sizeof(int)]; // Refresh
				retry = retry * 256 + (unsigned char)(*fromServer)[i + 2 * sizeof(int)]; // Retry
				expiration = expiration * 256 + (unsigned char)(*fromServer)[i + 3 * sizeof(int)]; // Expiration
				minimum = minimum * 256 + (unsigned char)(*fromServer)[i + 4 * sizeof(int)]; // Minimum
			}
			
			fprintf(dnsLogFile, "%s %s %i %i %i %i %i", textA, textB, serial, refresh, retry, expiration, minimum);

			(*fromServer) += 20;

			break;

		// prelucram mesajul primit de tipul text strings si il scriem
		// in fisierul dns.log in formatul din cerinta
		case TXT:
			textA = (char *)malloc((len + 1) * sizeof(char));
			
			(*fromServer)++;
			
			for(i = 0 ; i < len - 1; i++){ // Text
				textA[i] = (*fromServer)[i];
			}
			textA[len] = '\0';

			(*fromServer) += (len - 1);
			
			fprintf(dnsLogFile, "%s", textA);

			break;

		// prelucram mesajul primit de tipul domain name pointer si il scriem
		// in fisierul dns.log in formatul din cerinta
		case PTR: // reverse lookup
			textA = convertDnsToTextFormat(&(*fromServer)[0], buffer, &offset); // Addr
		
			fprintf(dnsLogFile, "%s", textA);

			(*fromServer) += offset;

			break;
		default:
			break;
	}

	fprintf(dnsLogFile, "\n");

	fclose(dnsLogFile);
}

void reverse(char * start, char * end){
	char aux;

	while(start < end){
		aux = *start;
		*start++ = *end;
		*end-- = aux;
	}
}

// functie utilizata pentru inversarea ordinii octetilor dintr-o
// adresa IP (de exemplu 1.2.3.4 devine 4.3.2.1)
void reverseWords(char * string){
	char * word = string;
	char * temp = string;

	while(*temp){
		temp++;

		if(*temp == '\0'){
			reverse(word, temp - 1);
		}else if(*temp == '.'){
			reverse(word, temp - 1);
			word = temp + 1;
		}
	}

	reverse(string, temp - 1);
}


int main(int argc, char * argv[]){
	char domain[100];
	char domainName[100];
	char dnsServersIPs[10][100];
	char queryType[10];
	char buffer[BUFLEN];

	// Citim adresele IP ale serverelor DNS din fisierul dns_servers.conf
	int j;
	int i = 0;
	FILE * serversConfFile = fopen(SERVERS_CONF_FILENAME, "r");

	while(fgets(buffer, BUFLEN, serversConfFile) != 0){
		if(buffer[0] != '\0' && buffer[0] != '#'){
			strcpy(dnsServersIPs[i], buffer);

			dnsServersIPs[i][strlen(dnsServersIPs[i]) - 1] = '\0';

			i++;
		}
	}

	fclose(serversConfFile);

	struct timeval timeout;
	// cate secunde asteptam raspunsul de la server pana la timeout
	timeout.tv_sec = TIMEOUT_SECONDS;
	timeout.tv_usec = 0;
	
	// Cream socket
	
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if(sockfd < 0){
  		printf("Eroare la creare socket.\n");
  	}

  	fd_set tempfd;
	FD_ZERO(&tempfd);
	FD_SET(sockfd, &tempfd);

	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(53); // portul 53 este portul standard dedicat pentru DNS
	
	int currentDnsIPAddressIndex = 0;

	strcpy(domainName, argv[1]);
	strcpy(domain, domainName);
	strcpy(queryType, argv[2]);

	int messageLogWrite = FALSE;

	while(1){
		inet_aton(dnsServersIPs[currentDnsIPAddressIndex], &serv_addr.sin_addr.s_addr);

		// Pregatim mesajul care trebuie trimis catre server-ul DNS pe baza argumentelor
		// date programului
	
		memset(buffer, 0, sizeof(buffer));
	
		dns_header_t * header = (dns_header_t *)buffer;
		memset(header, 0, sizeof(dns_header_t));
		header->id = (unsigned short)htons(getpid());
		header->qdcount = htons(1);
		header->rd = 1;

		strcpy(domain, domainName);

		// daca query type-ul este PTR, atunci inversam ordinea octetilor din adresa IP si
		// adaugam ".in-addr.arpa" la sfarsitul adresei ip pentru reverse lookup
		if(strcmp("PTR", queryType) == 0){
			reverseWords(domain);

			strcat(domain, ".in-addr.arpa");
		}

		convertTextToDnsFormat(domain, (char *)&buffer[sizeof(dns_header_t)]);
	
		dns_question_t * question = (dns_question_t *)&buffer[strlen(domain) + sizeof(dns_header_t) + 2];
			
		question->qclass = htons(1);

		int type = 0;

		if(strcmp("NS", queryType) == 0){
			type = NS;
		}else if(strcmp("A", queryType) == 0){
			type = A;
		}else if(strcmp("MX", queryType) == 0){
			type = MX;
		}else if(strcmp("CNAME", queryType) == 0){
			type = CNAME;
		}else if(strcmp("SOA", queryType) == 0){
			type = SOA;
		}else if(strcmp("TXT", queryType) == 0){
			type = TXT;
		}else if(strcmp("PTR", queryType) == 0){
			type = PTR;
		}

		question->qtype = htons(type);

		int sentMessageSize = sizeof(dns_header_t) + sizeof(dns_question_t) + strlen(domain) + 2;

		// scriem o singura data mesajul pe care il transmitem catre serverul DNS in
		// fisierul message.log in format hexa
		if(messageLogWrite == FALSE){
			messageLogWrite = TRUE;

			FILE * messageLogFile = fopen(MESSAGE_LOG_FILENAME, "a");

			int i;
			for(i = 0; i < sentMessageSize; i++){
				fprintf(messageLogFile, "%02x ", (unsigned int)(buffer[i] & 0xFF));
			}

			fprintf(messageLogFile, "\n");
			fclose(messageLogFile);
		}

		// Trimitem mesajul catre serverul DNS

		if(sendto(sockfd, buffer, sentMessageSize, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
			printf("Eroare la trimiterea mesajului catre serverul DNS.");

			currentDnsIPAddressIndex++;

			continue;				 	
		}

		memset(buffer, 0, BUFLEN);

		// Primim raspuns de la serverul DNS

		int r = select(sockfd + 1, &tempfd, NULL, NULL, &timeout);

		if(r < 0) {
			printf("Eroare la select.\n");

			currentDnsIPAddressIndex++;

			continue;
		}

		if(r == 0){
			printf("Eroare de timeout :(.\n");

			currentDnsIPAddressIndex++;

			continue;
		}

		int size;
		memset(buffer, 0, sizeof(buffer));

		if((r = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&serv_addr, (socklen_t *)&size)) < 0){
			printf("Eroare la primire mesaj de la server DNS.\n");

			currentDnsIPAddressIndex++;

			continue;
		}		

		header = (dns_header_t *)buffer;

		if(ntohs(header->ancount) == 0 && ntohs(header->nscount) == 0 && ntohs(header->arcount) == 0){
			currentDnsIPAddressIndex++;

			continue;
		}

		char * fromServer = &buffer[sizeof(dns_header_t) + strlen(domain) + sizeof(dns_question_t) + 2];
		
		// Scriem in fisierul dns.log mesajele din resource recordul de tipul Answer

		if(ntohs(header->ancount) > 0) {
			FILE * dnsLogFile = fopen(DNS_LOG_FILENAME, "a");
			fprintf(dnsLogFile, "; %s - %s %s\n\n;; ANSWER SECTION:\n",
				    dnsServersIPs[currentDnsIPAddressIndex], domain, queryType);
			fclose(dnsLogFile);

			for(j = 0; j < ntohs(header->ancount); j++){
				writeInDNSLog(buffer, &fromServer); // scriem mesajele propriu-zise
			}
		}

		// Scriem in fisierul dns.log mesajele din resource recordul de tipul Authority
		
		if(ntohs(header->nscount) > 0) {
			FILE * dnsLogFile = fopen(DNS_LOG_FILENAME, "a");
			fprintf(dnsLogFile, "; %s - %s %s\n\n;; AUTHORITY SECTION:\n",
				    dnsServersIPs[currentDnsIPAddressIndex], domain, queryType);
			fclose(dnsLogFile);

			for(j = 0; j < ntohs(header->nscount); j++){
				writeInDNSLog(buffer, &fromServer); // scriem mesajele propriu-zise
			}
		}

		// Scriem in fisierul dns.log mesajele din resource recordul de tipul Additional
		
		if(ntohs(header->arcount) > 0) {
			FILE * dnsLogFile = fopen(DNS_LOG_FILENAME, "a");
			fprintf(dnsLogFile, "; %s - %s %s\n\n;; ADDITIONAL SECTION:\n",
				    dnsServersIPs[currentDnsIPAddressIndex], domain, queryType);
			fclose(dnsLogFile);

			for(j = 0; j < ntohs(header->arcount); j++){
				writeInDNSLog(buffer, &fromServer); // scriem mesajele propriu-zise
			}
		}

		break;
	}

	FILE * dnsLogFile = fopen(DNS_LOG_FILENAME, "a");
	fprintf(dnsLogFile, "\n\n");
	fclose(dnsLogFile);

	return 0;
}
