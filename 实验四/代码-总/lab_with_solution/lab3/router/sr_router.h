/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include <stdbool.h>
#include "sr_protocol.h"
#include "sr_arpcache.h"

void sr_handle_ip(struct sr_instance* sr, uint8_t * buf, unsigned int len,char* interface);
struct sr_rt *prefix_match(struct sr_instance * sr, uint32_t addr);
void icmp_unreachable(struct sr_instance * sr, uint8_t code, sr_ip_hdr_t * ip, char* interface);
void handle_icmp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface);
void sr_icmp_echo(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip, char* interface);
int is_own_ip(struct sr_instance* sr, sr_ip_hdr_t* current);
void sr_handle_arp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface);
void send_arp_rep(struct sr_instance* sr, struct sr_if* iface, sr_arp_hdr_t* arp);
void icmp_time(struct sr_instance * sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip, char* interface);
void send_arp_req(struct sr_instance* sr, struct sr_if* iface, uint32_t ipadress,unsigned int len);

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_if_status_cache * if_cache; /* interfaces' status cache*/
    pthread_mutex_t rt_lock; 
    pthread_mutexattr_t rt_lock_attr;
    pthread_mutex_t rt_locker;
    pthread_mutexattr_t rt_locker_attr;
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    pthread_attr_t rt_attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

enum icmp_echo {
	Echoreply = 0, /*type=code=0*/
	Echorequest = 8
};

enum icmp_unreachables {
	t3_type = 3,
	Unreachable_net_code = 0,
  Unreachable_host_code = 1,
  Unreachable_port_code=3,
  Next_mtu=0,
  Unused=0
	/*ICMP_DESTINATION_HOST_UNREACHABLE_CODE = 1,
	ICMP_PORT_UNREACHABLE_CODE = 3,
	ICMP_NEXT_MTU = 0,
	ICMP_UNUSED = 0*/
};

enum icmp_ttl {
	TimeExceededType = 11,
	TimeExceededCode = 0
};

enum ip_defaults {
	iptos = 0,
	ipid = 0,
	ipoff = 0,
	ipttl = 100,
  broadcast_ip = 0xffffffff,
  invalid_ip=0x0
};

#endif /* SR_ROUTER_H */
