#pragma once
typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;

typedef unsigned char u_int8_t;
typedef signed char int8_t;
typedef unsigned short u_int16_t;
typedef signed short int16_t;
typedef unsigned int u_int32_t;
typedef signed int int32_t;
typedef unsigned long u_int64_t;
typedef signed long int64_t;

typedef	int bpf_int32;
typedef	u_int bpf_u_int32;

#define ETHERTYPE_IP 0x0800 /* ip protocol */
#define TCP_PROTOCAL 0x0600 /* tcp protocol */
#define UDP_PROTOCAL 0x1100 /* tcp protocol */
#define LINE_LEN 16
#define SP " "
#define SSP 1
#define CRLF "\r\n"
#define SCRLF 2
#define DCRLF "\r\n\r\n"
#define SDCRLF 4
#define HLEN "Content-Length"
#define SHLEN 14
#define ENCODE "Content-Encoding"
#define SENCODE 16
#define HOST "Host"
#define SHOST 4
#define CHUNKED "Transfer-Encoding"
#define SCHUNKED 17
struct pcap_pkthdr {
	long    tv_sec;
	long    tv_usec;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
};
struct ether_header {
	u_char ether_shost[6];
	u_char ether_dhost[6];
	u_short ether_type;
};

struct ip_header{
	u_int8_t  verl;
	u_int8_t  tos;            // 服务类型(Type of service) 
	u_int16_t tlen;           // 总长(Total length) 
	u_int16_t identification; // 标识(Identification)
	u_int16_t flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_int8_t  ttl;            // 存活时间(Time to live)
	u_int8_t  proto;          // 协议(Protocol)
	u_int16_t crc;            // 首部校验和(Header checksum)
	u_int8_t  saddr[4];		  // 源地址(Source address)
	u_int8_t  daddr[4];       // 目的地址(Destination address)
	u_int   op_pad;           // 选项与填充(Option + Padding)
};

struct tcp_header
{
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t seq;             /* sequence number */
	u_int32_t ack;             /* acknowledgement number */
	u_int16_t len_resv_code;   /* tcp头长，flag*/
	u_int16_t win;          
	u_int16_t sum;          
	u_int16_t urp;          
};
struct tcp_node {
	int count;
	u_int32_t seq;
	u_int32_t ack;
	u_int16_t flag;
	int offset;
	u_char *pkt_data;
	u_int caplen;
	int content_len;
	pcap_pkthdr pkth;
	bool dir;
	tcp_node * prev;
	tcp_node * next;
};
struct tcp_session {
	char saddr[16];
	char daddr[16];
	u_int16_t sprot;
	u_int16_t dprot;
	u_int8_t  proto;
	tcp_node * node_head;
	tcp_node * node_tail;
	tcp_session * next;
};
struct udp_header {
	u_int16_t sport;
	u_int16_t dport;
	u_int16_t len;
	u_int16_t crc;
};
struct udp_node{
	u_char *pkt_data;
	u_int caplen;
	pcap_pkthdr pkth;
	udp_node * prev;
	udp_node * next;
};
struct udp_session{
	char saddr[16];
	char daddr[16];
	u_int16_t sprot;
	u_int16_t dprot;
	udp_node * node_head;
	udp_node * node_tail;
	udp_session * next;
};
struct http_node {
	int count;
	u_char *content;
	u_int len;
	bool dir;
	http_node * prev;
	http_node * next;
};
struct http_session {
	int tcp_session;
	char saddr[16];
	char daddr[16];
	u_int16_t sprot;
	u_int16_t dprot;
	u_char *method;
	u_char *path;
	u_char * filename;
	u_char *ver;
	u_char *status;
	u_char *host;
	u_int req_len;
	u_int res_len;
	bool isGzip;
	bool isChunked;
	http_node * node_head;
	http_node * node_tail;
	http_session * next;
};