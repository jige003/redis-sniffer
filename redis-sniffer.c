/*************************************************************************
    > File Name: redis-sniffer.c
    > Author: jige003
 ************************************************************************/
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <time.h>
#include <signal.h>
#include <hiredis/hiredis.h>
#include <hiredis/read.h>

#define TCP_OFF(tcp) (tcp->doff*sizeof(uint32_t))

#define IP_HL(ip) ((4*ip->ip_hl))

#define dbg(fmt, ...) \
    do {\
        if (debug) {\
            fprintf(stderr, "\033[0;32m[+] "fmt, ##__VA_ARGS__); \
            fprintf(stderr, "\033[0m");\
        }\
    }while(0);

int debug = 0;
int sport = 0;
int dport = 0;

char tmpfp[256] = {0};
char sip[20] = {0};
char dip[20] = {0};

struct {
    char *device;
    char bufstr[256];
    int port;
}option = {
    .device = NULL,
    .bufstr = {0}, 
    .port = 6379
};

void Usage();

void px(char* tag, char*msg);

char* getTimeNow();

pcap_t* init_pcap_t(char* device, const char* bpfstr);

void sniff_loop(pcap_t* pHandle, pcap_handler func);

void packetHandle(u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data);

void bailout(int signo);

void printData(const char *data, int len);

int string2int(char *str);

int isstr(char *str, int len);

int query_parser(const u_char* pkt_data, unsigned int data_len, char **query);

int resp_parser(const u_char* pkt_data, unsigned int data_len, char **resp);

void xfree(void *ptr);

void Usage(){
    fprintf(stderr, "Copyright by jige003\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\tredissniffer [-h] -i interface -p port\n\n");
}

char* getTimeNow(){
    time_t tim;
    struct tm *at;
    static char now[80];
    time(&tim);
    at=localtime(&tim);
    strftime(now,79,"%Y-%m-%d %H:%M:%S",at);
    return now;
}


void px (char *tag, char *msg) {
    fprintf(stdout, "%s  %s:%d -> %s:%d [ %s ]  %s\n",getTimeNow(), sip, sport, dip, dport, tag, msg);
}

pcap_t* init_pcap_t(char* device, const char* bpfstr){
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *pHandle;

    uint32_t  srcip, netmask = -1;
    struct bpf_program bpf;

    if(!*device && !(device = pcap_lookupdev(errBuf))){
        printf("pcap_lookupdev(): %s\n", errBuf);
        return NULL;
    }

    printf("[*] sniffe on interface: %s\n", device);
    
    if((pHandle = pcap_open_live(device, 65535, 1, 0, errBuf)) == NULL){
        printf("pcap_open_live(): %s\n", errBuf);
        return NULL;
    }


    if (pcap_compile(pHandle, &bpf, (char*)bpfstr, 0, netmask)){
        printf("pcap_compile(): %s\n", pcap_geterr(pHandle));
        return NULL;
    }

    if (pcap_setfilter(pHandle, &bpf) < 0){
        printf("pcap_setfilter(): %s\n", pcap_geterr(pHandle));
        return NULL;
    }
    return pHandle;
}

void bailout(int signo){
    printf("ctr c exit\n");
    exit(0);
}

void sniff_loop(pcap_t* pHandle, pcap_handler func){
    int linktype, linkhdrlen=0;
 
    if ((linktype = pcap_datalink(pHandle)) < 0){
        printf("pcap_datalink(): %s\n", pcap_geterr(pHandle));
        return;
    }
    //printf("%d\n", linktype);
    switch (linktype){
    case DLT_RAW:
        linkhdrlen = 0;
        break;
        
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
    
    case DLT_LINUX_SLL:
        linkhdrlen = 16;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }
 
    if (pcap_loop(pHandle, -1, func, (u_char*)&linkhdrlen) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pHandle));   
    
}

void printData(const char *data, int len){
    int i = 0;
    for (; i < len; ++i ){
        char c = *(data+i);
        if (isprint(c)){
            printf("%c", c);
        }else{
            printf(".");
        }
    }
    printf("\n");
}

int string2int(char *str){
    char flag = '+';
    long res = 0;
    
    if(*str=='-')
    {
        ++str; 
        flag = '-'; 
    } 
    
    sscanf(str, "%ld", &res);
    if(flag == '-')
    {
        res = -res;
    }
    return (int)res;
}

int isstr(char *str, int len) {
    int f = 1;
    for(int i = 0; i < len; i++){
        if (!isprint(str[i])){
            f = 0;
            break;
        }
    }
    return f;
}

int query_parser(const u_char* pkt_data, unsigned int data_len, char **query){
        char **buf = query;
        int flag = 1;
        int params_len = 0, slen = 0;
        int start = 0;
        int llen = 0;
        u_char tmp[255] = {0};
        const u_char *p;

        dbg("pkt_data dat_len:%d\n", data_len);

        *buf = (char *)malloc(sizeof(char)* data_len);
        memset(*buf, 0, data_len);

        for (int i = 1; i < data_len; i ++ ){
            if (pkt_data[i] == 0x0d && pkt_data[i+1] == 0x0a) {
                    if (pkt_data[i+2] == 0x24 || i + 2 >= data_len) continue;
                    p = pkt_data + start + 1;
                    llen = i - start - 1;
                    if (flag == 1) {
                        memset(tmp, 0, sizeof(tmp));
                        memcpy(tmp, p, llen);
                        params_len = string2int((char *)tmp);
                    }else if (flag = 2){
                        memset(tmp, 0, sizeof(tmp));
                        memcpy(tmp, p, llen);
                        slen = string2int((char *)tmp);
                        memset(tmp, 0, sizeof(tmp));
                        p = pkt_data + i + 2;
                        memcpy(tmp, p, slen);
                        if (isstr(tmp, slen) == 1){
                            strncat(*buf, tmp, slen);
                            strcat(*buf, " ");
                        }
                    }
            }else if (pkt_data[i] == 0x24) {
                start = i;
                flag = 2;
            }
        }

        if (strlen(*buf) > 1 )
            return 0;
        return 1;
}

int resp_parser(const u_char* pkt_data, unsigned int data_len, char **resp){
    char **buf = resp;
    redisReader *reader;
    redisReply* r;
    void *reply;
    int ret;
    int j;

    reader = redisReaderCreate();
    redisReaderFeed(reader,(char*)pkt_data, data_len);
    
    dbg("reader len:%d\n", reader->len);

    *buf = (char *)malloc(sizeof(char) *reader->len);
    memset(*buf, 0, reader->len);
    ret = redisReaderGetReply(reader, &reply);
    if (ret == REDIS_OK && reply != NULL) {
        r = (redisReply* ) reply;

        dbg("reply type:%d\n", r->type);
        dbg("reply len:%d\n", r->len);

        if (r->type == REDIS_REPLY_STRING || r->type == REDIS_REPLY_STATUS) {
            strcpy(*buf, r->str);
        }else if (r->type == REDIS_REPLY_INTEGER) {
            sprintf(*buf, "%d", r->integer);
        }else if (r->type == REDIS_REPLY_NIL) {
            sprintf(*buf, "%s", "nil");
        }else if (r->type == REDIS_REPLY_ERROR) {
            strcpy(*buf, r->str);
        }else if (r->type == REDIS_REPLY_ARRAY) {
            for (j = 0; j < r->elements; j++) {
                if (debug)
                    dbg("%u) %s %d \n", j, r->element[j]->str, r->element[j]->len);
                strncat(*buf, r->element[j]->str, r->element[j]->len);
                strcat(*buf, " ");
            }
        }else {
            sprintf(*buf, "%s", "packet parser error");
        }
    }


    freeReplyObject(reply);
    redisReaderFree(reader);
    
    if (strlen(*buf) > 1 )
        return 0;
    
    return 1;
}

void xfree(void *ptr) {
    if (ptr != NULL) 
        free(ptr);
}

void packetHandle(u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data){
    int *linkhdrlen = (int*) arg;
    unsigned int data_len,  r;
    struct ether_header* pehdr;
    struct ip* piphdr;
    struct tcphdr* ptcphdr;
    if ( !pkt_data ){
        printf ("Didn't grab packet!/n");
        exit (1);
    }
    if (header->caplen < header->len) return;
    pehdr = (struct ether_header*)pkt_data;
    pkt_data += *linkhdrlen;
    
    piphdr = (struct ip*)pkt_data;
    pkt_data += IP_HL(piphdr);
    data_len = ntohs(piphdr->ip_len) - IP_HL(piphdr);
    switch(piphdr->ip_p){
        case IPPROTO_TCP:
            ptcphdr = (struct tcphdr*)pkt_data;
            data_len = data_len - TCP_OFF(ptcphdr);
            pkt_data += TCP_OFF(ptcphdr);
            strcpy(sip, inet_ntoa(piphdr->ip_src));
            strcpy(dip, inet_ntoa(piphdr->ip_dst));
            sport = ntohs(ptcphdr->source);
            dport = ntohs(ptcphdr->dest);
            break;
        default:
            data_len = 0;
            pkt_data = NULL;
            break;
    }
    if (data_len == 0 || pkt_data == NULL ) return;

    char *query;   
    if (pkt_data[0] == 0x2a && dport == option.port) {
        if (! query_parser(pkt_data, data_len, &query))
            px("req", query);
    }else {
        if (! resp_parser(pkt_data, data_len, &query)) 
            px("resp", query);
    }

    xfree(query);

    signal(SIGINT, bailout);
    signal(SIGTERM, bailout);
    signal(SIGQUIT, bailout);
}   


int main(int argc, char **argv){
    char *device;
    char bpfstr[256] = "port 6379";

    pcap_t* pHandle;
    
    int i;
    
    if (argc < 2 ){
        Usage();
        return -1;
    }

    while ((i = getopt(argc, argv, "hi:p:")) != -1) {
        switch(i){
            case 'h':
                Usage();
                return -1;
                break;
            case 'i':
                option.device = optarg;
                break;
            case 'p':
                option.port = atoi(optarg);
                break;
            default:
                break;
        }
    }

    sprintf(option.bufstr, "port %d", option.port);

    char *d = getenv("jdebug");
    if ( d != NULL &&  !strcmp(d, "true")) 
        debug = 1;
    
    dbg("debug mode\n");

    if((pHandle = init_pcap_t(option.device, option.bufstr))){
        sniff_loop(pHandle, (pcap_handler)packetHandle);
    }    
    exit(0);

}

