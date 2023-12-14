/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"



/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t arp_thread;

  pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);

  srand(time(NULL));
  pthread_mutexattr_init(&(sr->rt_lock_attr));
  pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

  pthread_attr_init(&(sr->rt_attr));
  pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t rt_thread;
  pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);

} 

/*---------------------------------------------------------------------
 * Method: sr_handlepacket
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* interface)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  uint16_t ethtype = ethertype(packet);

  /* Handle packet based on EtherType */
  switch(ethtype) {
    case ethertype_arp:
      /* Lab4-Task2 TODO: if the EtherType=0x0806, the payload of Ethernet frame is an ARP packet. Pass the packet to the next layer, strip the low level header. */
      sr_handle_arp(sr, packet+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t), interface);
      /*End TODO*/
      break;
    case ethertype_ip:
      /* Lab4-Task2 TODO: if the EtherType=0x0800, the payload of Ethernet frame is an IP packet. Pass the packet to the next layer, strip the low level header. */
      sr_handle_ip(sr, packet, len-sizeof(sr_ethernet_hdr_t), interface);
      /*End TODO*/
      break;
  }
}


/*---------------------------------------------------------------------
 * Method: send_arp_req() 
 * IP Stack Level: Link Layer
 * @brief function sends an ARP request 
 * @param sr: pointer to simple router state.
 * @param iface: record of the interface sending the packet 
 * @param ipadress: the ip address that needs to find its MAC address 
 * @param len: length of all headers 
 * *
 *---------------------------------------------------------------------*/
void send_arp_req(struct sr_instance* sr, struct sr_if* iface, uint32_t ipadress, unsigned int len){
  /*int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);*/
  uint8_t *block = (uint8_t *) malloc(len);
  memset(block, 0, sizeof(uint8_t) * len);
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));

  /* Lab4-Task2 TODO: Set the source and destination MAC addresses in the Ethernet frame for an ARP request */
  memcpy(ethernet_hdr->ether_shost, iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memset(ethernet_hdr->ether_dhost, 0xff, sizeof(uint8_t) * ETHER_ADDR_LEN);
  /* End TODO */
  ethernet_hdr->ether_type = htons(ethertype_arp);

  arp_hdr->ar_op = htons(arp_op_request);
  memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN); 
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_pln = sizeof(uint32_t);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_tip = ipadress;
  arp_hdr->ar_sip = iface->ip;
  print_hdrs((uint8_t*) block, len);
  sr_send_packet(sr, block, len, iface->name);
  free(block);
}





/*---------------------------------------------------------------------
 * Method: sr_handle_ip() 
 * IP Stack Level: Network Layer
 * @brief function handles a received IPv4 packet. 
 * @param sr: pointer to simple router state.
 * @param buf: pointers to received Ethernet Frame.
 * @param len: length of the header
 * @param interface:  
 * *
 *---------------------------------------------------------------------*/
void sr_handle_ip(struct sr_instance* sr, uint8_t * buf, unsigned int len,char* interface){
  /*2.a Check whether the checksum in the IP header is correct. 
    If the checksum is not correct, just ignore this packet and return. 
    Recall the Internet checksum algorithm returns zero if there is no bit error*/
  /*Extract the ip header from the Ethernet frame*/
  sr_ip_hdr_t* ip = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t)); 
  uint16_t received = ip->ip_sum; 
  ip->ip_sum = 0;
  uint16_t calc = cksum(ip,sizeof(sr_ip_hdr_t));
  /*something went wrong with checksum*/
  if(calc!=received){
    return;
  }
  ip->ip_sum = calc; 

  if(ip->ip_dst==broadcast_ip){
    sr_udp_hdr_t* udp = (sr_udp_hdr_t*) (buf+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
    if(udp->port_src==520 && udp->port_dst==520){
      /* send rip packet*/
      sr_rip_pkt_t* rip = (sr_rip_pkt_t*) (buf+sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_ethernet_hdr_t));

      if(rip->command==1){/*it's a request?*/
        /*printf("it's a rip request\n");*/
        send_rip_response(sr);
      }
      else{/*it's a reply?*/
        /*printf("it's a rip reply\n");*/
        update_route_table(sr,(uint8_t*)buf,len,interface);
      }
    }
    else{
      /*printf("ip->ip_p is not udp\n");*/
      icmp_unreachable(sr, Unreachable_port_code, ip, interface);
    }
  }
  else{
    int i = is_own_ip(sr,ip);
    /*2.b If the destination IP of this packet is router’s own IP */
    
    if(i==1){ 
      /*2.b.1 is ICMP*/
      if (ip->ip_p == ip_protocol_icmp) {
        handle_icmp(sr, buf+sizeof(sr_ethernet_hdr_t) , len , interface);
      }
      /*2.b.2 is unreachable, we do not consider other protocols here*/
      else{
        icmp_unreachable(sr, Unreachable_port_code, ip, interface);
      }
    }
    /* the corresponding interface is down */
    else if(i==2){ 
      icmp_unreachable(sr, Unreachable_net_code, ip, interface);
    }


    /*2.c If the destination IP is not router's own IP*/
    else{
      /*2.c.1 Check whether the TTL in the IP header equals 1. 
        If TTL=1, your router should reply an ICMP Time Exceeded message back to the Sender*/
      if(ip->ip_ttl == 1){
        /* Lab4-Task2 TODO: reply an ICMP Time Exceeded message back to the sender */
        icmp_time(sr, TimeExceededType, TimeExceededCode, (sr_ip_hdr_t *)ip, interface);
        /* End TODO */
      }
      else{
        /*2.c.2 Otherwise, check whether the destination IP address is in your routing table.*/
        /*If you can not find this destination IP in your routing table, 
          you should send an ICMP DEST_NET_UNREACHABLE message back to the Sender. 
          You should implement a Longest Prefix Matching here.*/
        struct sr_rt * match = prefix_match(sr,ip->ip_dst);
        
        if(match==NULL){
          /* Lab4-Task2 TODO: reply an ICMP destination net unreachable message back to the sender */
          icmp_unreachable(sr, Unreachable_net_code, ip, interface);
          /* End TODO */
        }
        else{
          if(sr_obtain_interface_status(sr,match->interface)!=0){
            /*2.c.3.i Decrement TTL*/
            ip -> ip_ttl -= 1;
            
            /*2.c.3.ii Recalculate the checksum*/
            ip -> ip_sum = 0;
            ip -> ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
            
            /*2.c.3.iii Change the Source MAC Address, Destination MAC Address in the ethernet header*/
            uint8_t * block = malloc(ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t));
            sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
            memcpy(pkt, ip, ntohs(ip->ip_len));
            /*Get the source interface record*/
            struct sr_if *srcMac = sr_get_interface(sr, interface); 
            /*Get the forwarding interface record*/
            struct sr_if *iface2 = sr_get_interface(sr, match->interface); 
            sr_ethernet_hdr_t* start_of_pckt = (sr_ethernet_hdr_t*) block;
            struct sr_arpentry * entry;
            /*indirect delivery*/
            if(match->gw.s_addr != 0){
              /* Lab4-Task2 TODO: find the MAC addr in arp cache of the next hop ip */
              entry = sr_arpcache_lookup(&(sr->cache), match->gw.s_addr); 
              /* End TODO */
            }
            /*direct delivery, the destination is on the same network as the sending host*/
            else{ 
              /* Lab4-Task2 TODO: find the MAC addr in arp cache of the destination ip */
              entry = sr_arpcache_lookup(&(sr->cache), ip->ip_dst);
              /* End TODO */
            }
            /*2.c.3.iii(1) if find the MAC addr successfully, send modified packet immediately*/
            if(entry!=NULL){ 
              memcpy((void *) (start_of_pckt->ether_shost), iface2->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
              unsigned char value[ETHER_ADDR_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
              if(entry->mac==value){ 
                memcpy((void *) (start_of_pckt->ether_dhost),  &ip->ip_dst, sizeof(uint8_t) * ETHER_ADDR_LEN);
              }
              else{
                memcpy((void *) (start_of_pckt->ether_dhost), entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
              }
              start_of_pckt->ether_type = htons(ethertype_ip);
              sr_send_packet(sr, block, ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t), match->interface);
              free(block);
            }
            /*Ideally, you should find the Destination MAC Address in your ARP cache using the 
              Destination IP Address. If you can find the destination MAC address, then you can 
              just send this modified packet immediately. However, it is possible that your current
              ARP cache did not contain the information of the destination IP. In this case, you should 
              not send this modified packet since you lack the destination MAC Address. Therefore, 
              you should send an ARP request to the out interface, and cache the modified IP packet 
              in the ARP request queue. Once you received the arp response, you can send all the
                pending packets according to this destination MAC address inside the queue*/
            
            /*2.c.3.iii(2) arp cache did not contain dest IP, send arp request to find the MAC address*/
            else  { 
              /*direct delivery*/
              if(match->gw.s_addr == 0){ 
                sr_arpcache_queuereq(&sr->cache, ip->ip_dst, (uint8_t *) block, ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t), match->interface);
              }
              /*indirect delivery*/ 
              else{ 
                sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, (uint8_t *) block, ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t), match->interface);
              }
              /* Lab4-Task2 TODO: Send an ARP request to the out interface */
              send_arp_req(sr, iface2, ip->ip_dst, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
              /* End TODO */
              free(block);
            }      
            
          }
          else{ 
            /*match not null but match interface down*/
            icmp_unreachable(sr, Unreachable_net_code, ip, interface);
          }
        }
      }
    }
  }
}




/**
 * icmp_time()
 * IP Stack Level: Network (IP)
 * @brief Function sends ICMP Time Exceeded message back to the Sender.
 * @param sr: pointer to simple router state.
 * @param type: ICMP type
 * @param code: ICMP subtype
 * @param ip: the received ip packet
 * @param interface: the interface that sends the ICMP packet. 
 */
void icmp_time(struct sr_instance * sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip, char* interface){
  uint8_t * block = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len));

  /*1. Set Ethernet header: source MAC, destination MAC, EtherType*/
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  struct sr_if * iface = sr_get_interface(sr, interface);
  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);

  if(entry==NULL){
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  }
  else{
    memcpy(ethernet_hdr->ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
  }
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  ethernet_hdr->ether_type = htons(ethertype_ip);


  /*2. Set ip header: source IP, destination IP, checksum, protocol*/
  uint32_t ip_src = ntohl(ip->ip_dst);
  uint32_t ip_dst= ntohl(ip->ip_src);
  sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
  memcpy(pkt, ip, ntohs(ip->ip_len));
  pkt->ip_hl = 0x5;
  pkt->ip_v  = 0x4;
  pkt->ip_tos = iptos;
  pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t)));
  pkt->ip_id = htons(ipid);
  pkt->ip_off = htons(ipoff);
  pkt->ip_ttl = ipttl;
  pkt->ip_p = ip_protocol_icmp;
  pkt->ip_sum = 0;
  pkt->ip_src = sr_get_interface(sr, interface)->ip;
  pkt->ip_dst = htonl(ip_dst);
  pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));

  /*3. Set ICMP header: type, code, checksum*/
  sr_icmp_t11_hdr_t* icmp_t11_hdr = (sr_icmp_t11_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_t11_hdr->icmp_type = type;
  icmp_t11_hdr->icmp_code = code;
  icmp_t11_hdr->icmp_sum = 0;
  icmp_t11_hdr->unused = Unused;
  memcpy((icmp_t11_hdr->data), (uint8_t *) ip, sizeof(uint8_t) * ICMP_DATA_SIZE);
  icmp_t11_hdr->icmp_sum = cksum((void *)icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));

  /*4.Send this ICMP Reply packet back to the Sender*/
  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
  sr_send_packet(sr, block, packet_len, interface );
  free(block);
}

/**
 * prefix_match()
 * IP Stack Level: Network (IP)
 * @brief Function performs longest prefix match.
 * @param sr: pointer to simple router state.
 * @param addr: ip destination address. 
 */
struct sr_rt *prefix_match(struct sr_instance * sr, uint32_t addr){
  struct sr_rt * table = sr->routing_table;
  int max_len = -1;
  struct sr_rt * ans = NULL;

  while (table != NULL) {
    in_addr_t left = (table->mask.s_addr & addr);
    in_addr_t right = (table->dest.s_addr & table->mask.s_addr);
    if (left == right && table->metric < INFINITY) {
      uint8_t size = 0;
      uint32_t checker = 1 << 31;
      while ((checker != 0) && ((checker & table->mask.s_addr) != 0)) {
        size++;
        checker = checker >> 1;
      }
      if (size > max_len) {
        max_len = size;
        ans = table;
      }
    }
    table = table->next;
  }
  return ans;
}


/**
 * icmp_unreachable()
 * IP Stack Level: Network (IP)
 * @brief Function send ICMP unreachable message.
 * @param sr: pointer to simple router state.
 * @param code: ICMP subtype. 
 * @param ip: ip header. 
 * @param interface: pointer to interface ICMP packet was received. 
 */
void icmp_unreachable(struct sr_instance * sr, uint8_t code, sr_ip_hdr_t * ip, char* interface){

  uint8_t * block = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len));

  /*1. Set Ethernet header: source MAC, destination MAC, Ethertype*/
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  struct sr_if * iface = sr_get_interface(sr, interface);
  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);
  if(entry==NULL){
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  }
  else{
    memcpy(ethernet_hdr->ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
  }
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  ethernet_hdr->ether_type = htons(ethertype_ip);


  /*2. Set ip header: source ip, destination ip, ttl, len, sum*/
  uint32_t ip_src = ntohl(ip->ip_dst);
  uint32_t ip_dst= ntohl(ip->ip_src);
  sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
  memcpy(pkt, ip, ntohs(ip->ip_len));
  pkt->ip_hl = 0x5;
  pkt->ip_v  = 0x4;
  pkt->ip_tos = iptos;
  pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)));
  pkt->ip_id = htons(ipid);
  pkt->ip_off = htons(ipoff);
  pkt->ip_ttl = ipttl;
  pkt->ip_p = ip_protocol_icmp;
  pkt->ip_sum = 0;
  pkt->ip_src = sr_get_interface(sr, interface)->ip;
  pkt->ip_dst = htonl(ip_dst);
  pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));

  /*3. Set ICMP header: type, code, checksum*/
  sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_t3_hdr->icmp_type = t3_type;
  icmp_t3_hdr->icmp_code = code;
  icmp_t3_hdr->next_mtu = Next_mtu;
  icmp_t3_hdr->icmp_sum = 0;
  icmp_t3_hdr->unused = Unused;
  memcpy((icmp_t3_hdr->data), (uint8_t *) ip, sizeof(uint8_t) * ICMP_DATA_SIZE);
  icmp_t3_hdr->icmp_sum = cksum((void *)icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

  /*4. Send this ICMP Reply packet back to the Sender*/
  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  sr_send_packet(sr, block, packet_len, interface );
  free(block);
}

/**
 * handle_icmp()
 * IP Stack Level: Network (IP)
 * @brief Function handles ICMP packet.
 * @param sr: pointer to simple router state.
 * @param buf: pointer to received ICMP packet. 
 * @param len: number of valid ICMP packet bytes. 
 * @param interface: pointer to interface ICMP packet was received. 
 */
void handle_icmp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface){
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(buf);
  sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (((void *) buf)+ sizeof(sr_ip_hdr_t));
  uint8_t type = icmp_hdr->icmp_type;
  /*2.b.1 Check the ICMP packet type*/
  /*2.b.1.i It is ICMP ECHO request*/
  if(type==Echorequest){
    sr_icmp_echo(sr, Echoreply, Echoreply, ip_hdr, interface);
  }
  /*2.b.1.ii It is not an ICMP ECHO packet, your router can ignore this packet*/
  else{
    /*printf("ignoring packet\n");*/
  }
}

/**
 * sr_icmp_echo()
 * IP Stack Level: Network (IP)
 * @brief Function send ICMP echo message.
 * @param sr: pointer to simple router state.
 * @param type: ICMP type. 
 * @param code: ICMP subtype.
 * @param ip: ip header
 * @param interface: pointer to interface ICMP packet was send. 
 */
void sr_icmp_echo(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip, char* interface){
  /*2.b.1.i(1) Malloc a space to store ethernet header and IP header and ICMP header*/
  uint8_t * block = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len));
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  /*2.b.1.i(2) Fill the Source MAC Address, Destination MAC Address, Ethernet Type in ethernet header*/
  struct sr_if * iface = sr_get_interface(sr, interface);
  /*source MAC is the address of interface*/
  memcpy(ethernet_hdr->ether_shost, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);  

  /*Lookup ARP cache to find destination MAC*/ 
  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);

  if(entry==NULL){   
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  }
  else{
    memcpy(ethernet_hdr->ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
  }

  ethernet_hdr->ether_type = htons(ethertype_ip);
  
  /*2.b.1.i(3) Fill the source IP address, destination IP address, ttl, protocol, length, checksum in IP header*/
  uint32_t ip_src = ntohl(ip->ip_dst);
  uint32_t ip_dst= ntohl(ip->ip_src);
  sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
  memcpy(pkt, ip, ntohs(ip->ip_len));
  pkt->ip_hl = 0x5;
  pkt->ip_v  = 0x4;
  pkt->ip_tos = iptos;
  pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t8_hdr_t)));
  pkt->ip_id = htons(ipid);
  pkt->ip_off = htons(ipoff);
  pkt->ip_ttl = ipttl;
  pkt->ip_p = ip_protocol_icmp;
  pkt->ip_sum = 0;
  pkt->ip_src = htonl(ip_src);
  pkt->ip_dst = htonl(ip_dst);
  pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));

  /*2.b.1.i(4) Fill the ICMP code, type in ICMP header*/
  sr_icmp_t8_hdr_t* icmp_hdr = (sr_icmp_t8_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum  = 0;
  icmp_hdr->icmp_sum = cksum((void *)icmp_hdr, sizeof(sr_icmp_t8_hdr_t));

  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len);
  
  /*2.b.1.i(5) Send this ICMP Reply packet back to the Sender*/
  /*print_hdr_eth((uint8_t *)block);
    print_hdr_ip((uint8_t *)(block + sizeof(sr_ethernet_hdr_t) ));
    print_hdr_icmp((uint8_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    print_hdrs((uint8_t*) block, packet_len);*/
  sr_send_packet(sr, block, packet_len, interface );
  free(block);
}



/**
 * is_own_ip()
 * IP Stack Level: Network (IP)
 * @brief Function checks if ANY of our IP addresses matches the packet's destination IP.
 * @param sr: pointer to simple router state.
 * @param current: packet pointer to received ip packet.
 * @return 0: we were not the destination of this packet.
 *         1: we were the destination and the interface is up
 *         2: we were the destination, but the interface is down 
 */
int is_own_ip(struct sr_instance* sr, sr_ip_hdr_t* current) {
  int value = 0;
  struct sr_if * iface = sr->if_list;
  while (iface != NULL) {
    if (current->ip_dst == iface->ip && sr_obtain_interface_status(sr,iface->name)!=0) {
      return 1;
    }
    else if(current->ip_dst == iface->ip && sr_obtain_interface_status(sr,iface->name)==0) {
      value = 2;
    }
    iface = iface->next;
  }
  if(value==2) return 2;
  return 0;
}

/**
 * sr_handle_arp()
 * IP Stack Level: Link Layer 
 * @brief Function handles arp packet.
 * @param sr: pointer to simple router state.
 * @param buf: pointer to received arp packet. 
 * @param len: number of valid ARP packet bytes. 
 * @param interface: pointer to interface ARP packet was received. 
 */
void sr_handle_arp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface) {
  sr_arp_hdr_t* arp = (sr_arp_hdr_t*) buf;
  enum sr_arp_opcode op = (enum sr_arp_opcode)ntohs(arp->ar_op);
  struct sr_if* iface = sr_get_interface(sr, interface);

  /*1.a. It is an ARP request*/
  if(op==arp_op_request){
    
    /*1.a.1 Insert the Sender MAC in this packet to your ARP cache*/
    /* Lab4-Task2 TODO: Insert (sender MAC, sender ip) to ARP cache */
    struct sr_arpreq * pending = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip); 
    /* End TODO */ 
    /*1.a.1i If pending is happening in request, send pending request one by one */ 
    if (pending) {
      struct sr_packet *current = pending->packets;
      while (current) { 
        uint8_t *packet = current->buf;
        sr_ethernet_hdr_t *curheader = (sr_ethernet_hdr_t *)packet;
        memcpy(curheader->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
        memcpy(curheader->ether_shost, iface->addr, ETHER_ADDR_LEN);
        curheader->ether_type = htons(ethertype_ip);
        sr_send_packet(sr, packet, current->len, interface);
        current = current->next;
      }
      sr_arpreq_destroy(&(sr->cache), pending);
    }
  
    /*1.a.2 Send reply to the request*/
    send_arp_rep(sr, iface, arp); 
  }
  /*1.b. It is an ARP reply*/
  if(op==arp_op_reply){
    /* 1.b.1 Insert the Target MAC to your ARP cache*/
    /* Lab4-Task2 TODO: Insert (MAC, ip) included in the reply into ARP cache */
    struct sr_arpreq * pending = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
    /* End TODO */
    /* 1.b.1.i pending is happening in reply*/
    if (pending) {
      struct sr_packet *current = pending->packets;
      while (current!=NULL) { 
        uint8_t *packet = current->buf;
        sr_ethernet_hdr_t *curheader = (sr_ethernet_hdr_t *)packet;
        memcpy(curheader->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
        memcpy(curheader->ether_shost, iface->addr, ETHER_ADDR_LEN);
        curheader->ether_type = htons(ethertype_ip);
        sr_send_packet(sr, packet, current->len, interface);
        current = current->next;
      }
      sr_arpreq_destroy(&(sr->cache), pending);
    }
  }
}

/*---------------------------------------------------------------------
 * Method: send_arp_rep() 
 * IP Stack Level: Link Layer
 * @brief function sends an ARP reply 
 * @param sr: pointer to simple router state.
 * @param iface: record of the interface sending the packet 
 * @param arp: the arp header of the received arp request packet 
 * *
 *---------------------------------------------------------------------*/

void send_arp_rep(struct sr_instance* sr, struct sr_if* iface, sr_arp_hdr_t* arp){

  /* 1 Malloc a space to store an Ethernet header and ARP header */
  uint8_t* block = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* ethhdr = (sr_ethernet_hdr_t*)(block);

  /* 2 Fill the ARP opcode, Sender IP, Sender MAC, Target IP, Target MAC in ARP header*/
  arphdr->ar_hrd = htons(arp_hrd_ethernet);
  arphdr->ar_pro = htons(0x0800);
  arphdr->ar_hln = ETHER_ADDR_LEN;
  arphdr->ar_pln = sizeof(uint32_t);
  arphdr->ar_op  = htons(arp_op_reply);
  memcpy(arphdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arphdr->ar_sip = iface->ip;
  memcpy(arphdr->ar_tha, arp->ar_sha, ETHER_ADDR_LEN);
  arphdr->ar_tip = arp->ar_sip;

  /* 3 Fill the Source MAC Address, Destination MAC Address, Ethernet Type in the Ethernet header */
  memcpy(ethhdr->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
  memcpy(ethhdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  ethhdr->ether_type = htons(ethertype_arp);

  /* 4 Send this ARP response back to the Sender */
  sr_send_packet(sr, block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), iface->name);
  free(block);
  return;
}
