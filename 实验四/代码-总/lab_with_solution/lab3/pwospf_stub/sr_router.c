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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
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
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
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
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  if (length < sizeof(sr_ethernet_hdr_t))
   {
      /* Ummm...this packet doesn't appear to be long enough to 
       * process... Drop it like it's hot! */
      return;
   }
   
   receivedInterfaceEntry = sr_get_interface(sr, interface);
   
   if ((receivedInterfaceEntry == NULL)
      || ((memcmp(GET_ETHERNET_DEST_ADDR(packet), receivedInterfaceEntry->addr, ETHER_ADDR_LEN) != 0)
         && (memcmp(GET_ETHERNET_DEST_ADDR(packet), broadcastEthernetAddress, ETHER_ADDR_LEN) != 0)))
   {
      /* Packet not sent to our Ethernet address? */
      LOG_MESSAGE("Dropping packet due to invalid Ethernet receive parameters.\n");
      return;
   }
   
   switch (ethertype(packet))
   {
      case ethertype_arp:
         /* Pass the packet to the next layer, strip the low level header. */
         linkHandleReceivedArpPacket(sr, (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)),
            length - sizeof(sr_ethernet_hdr_t), receivedInterfaceEntry);
         break;
         
      case ethertype_ip:
         /* Pass the packet to the next layer, strip the low level header. */
         networkHandleReceivedIpPacket(sr, (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)),
            length - sizeof(sr_ethernet_hdr_t), receivedInterfaceEntry);
         break;
         
      default:
         /* We have no logic to handle other packet types. Drop the packet! */
         LOG_MESSAGE("Dropping packet due to invalid Ethernet message type: 0x%X.\n", ethertype(packet));
         return;
   }
}/* end sr_ForwardPacket */

void sr_handle_ip(struct sr_instance* sr, uint8_t * buf, unsigned int len,char* interface){
  /*2a Check whether the checksum in the IP header is correct. 
  If the checksum is not correct, just ignore this packet and return. 
  Recall the Internet checksum algorithm returns zero if there is no bit error*/
  /*print_hdrs(buf,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));*/
  sr_ip_hdr_t* ip = (sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));
  uint16_t received = ip->ip_sum;
  ip->ip_sum = 0;
  uint16_t calc = cksum(ip,sizeof(sr_ip_hdr_t));
  if(calc!=received){
    /*printf("something went wrong with checksum");*/
    return;
  }
  ip->ip_sum = calc;
  /*if(cksum(ip,sizeof(sr_ip_hdr_t))!=0){
    printf("something went wrong with checksum");
    return;
  }*/
  /*printf("checksum fine\n");*/

  /*LAB 5 1A*/
  if(ip->ip_dst==broadcast_ip){

    /*printf("ip->ip_dst==broadcast_ip\n");*/
    /*LAB 5 1Ai*/
    if(ip->ip_p==ip_protocol_udp){

      sr_udp_hdr_t* udp = (sr_udp_hdr_t*) (buf+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
      /*LAB 5 1Ai1*/
      
	if(udp->port_src==520 && udp->port_dst==520){

        /* send rip packet*/
        sr_rip_pkt_t* rip = (sr_rip_pkt_t*) (buf+sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_ethernet_hdr_t));
        /*LAB5 1ai1a*/
        if(rip->command==1){/*it's a request?*/

          /*printf("it's a rip request\n");*/
          send_rip_response(sr);
        }
        /*LAB5 1ai1b*/
        else{/*it's a reply?*/

          /*printf("it's a rip reply\n");*/
          update_route_table(sr,(uint8_t*)buf,len,interface);
        }

      }

      /*LAB 5 1Ai2*/
      else{
        /*printf("ip->ip_p is not udp\n");*/
        icmp_unreachable(sr, Unreachable_port_code, ip, interface);
      }
    }
  }

  else{
    /*2b If the destination IP of this packet is router’s own IP */
    int i = is_own_ip(sr,ip);
    if(i==1){
      /*printf("is own ip\n");*/
      /*LAB 5 1bi*/
      if(sr_obtain_interface_status(sr,interface)!=0){
        /*2b1 */
        /*printf("sr_obtain_interface_status(sr,interface) is %d\n",sr_obtain_interface_status(sr,interface));
        printf(" interface is %s\n",interface);*/
 
        if (ip->ip_p == ip_protocol_icmp) {
          /*printf("isicmp\n");*/
          handle_icmp(sr, buf+sizeof(sr_ethernet_hdr_t) , len , interface);
        }
        /*2b2 */
        else{
          /*printf("is unreachable\n");*/
          icmp_unreachable(sr, Unreachable_port_code, ip, interface);
        }
      }
      /*LAB 5 1bi*/
      else{
        /*printf("lab5 interface down\n");*/
        icmp_unreachable(sr, Unreachable_net_code, ip, interface);
      }

    }
    else if(i==2){
      icmp_unreachable(sr, Unreachable_net_code, ip, interface);
    }
    /*2c*/
    else{
      /*2c1 Check whether the TTL in the IP header equals 1. 
      If TTL=1, your router should reply an ICMP Time Exceeded message back to the Sender*/
      /*printf("\n******ttl is %i*******\n", ip->ip_ttl);*/
      if(ip->ip_ttl == 1){
        icmp_time(sr, TimeExceededType, TimeExceededCode, (sr_ip_hdr_t *)ip, interface);
      }
      else{
        /*2c2 Otherwise, check whether the destination IP address is in your routing table.*/
        /*If you can not find this destination IP in your routing table, 
        you should send an ICMP DEST_NET_UNREACHABLE message back to the Sender. 
        You should implement a Longest Prefix Matching here.*/
        struct sr_rt * match = prefix_match(sr,ip->ip_dst);

        /*struct in_addr ipdst;
        ipdst.s_addr = ip->ip_dst;
        printf("ip destination %s\n", inet_ntoa(ipdst));
        sr_print_routing_entry(match);*/
        if(match==NULL){
          
          icmp_unreachable(sr, Unreachable_net_code, ip, interface);
        }
        else{
          /*LAB5 1bii*/
          if(sr_obtain_interface_status(sr,match->interface)!=0){
            /*2c3*/
            /*printf("2c3\n");*/
            ip -> ip_ttl -= 1;
            /*2c3ii Recalculate the checksum*/
            ip -> ip_sum = 0;
            ip -> ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
            /*2c3iii Change the Source MAC Address, Destination MAC Address in the ethernet header*/
            
            uint8_t * block = malloc(ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t));
            sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
            memcpy(pkt, ip, ntohs(ip->ip_len));
            struct sr_if *srcMac = sr_get_interface(sr, interface);
            struct sr_if *iface2 = sr_get_interface(sr, match->interface);
            sr_ethernet_hdr_t* start_of_pckt = (sr_ethernet_hdr_t*) block;
            /*save sr_arpcache_ lookup as struct sr_arp_entry, put that in if(sr_arp = true), */
            struct sr_arpentry * entry;
            /*LAB5 1b2*/
            /*printf("match gwsaddr is %s\n",inet_ntoa(match->gw));*/
            if(match->gw.s_addr != 0){
              entry = sr_arpcache_lookup(&(sr->cache), match->gw.s_addr);
            }
            else{
              entry = sr_arpcache_lookup( &(sr->cache), ip->ip_dst);
            }
            if(entry!=NULL){
              /*printf("2c3 entry not null\n");*/
              memcpy((void *) (start_of_pckt->ether_shost), iface2->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
              /*LAB5 2*/
              unsigned char value[ETHER_ADDR_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
              if(entry->mac==value){ 
                memcpy((void *) (start_of_pckt->ether_dhost),  &ip->ip_dst, sizeof(uint8_t) * ETHER_ADDR_LEN);
              }
              else{
                memcpy((void *) (start_of_pckt->ether_dhost), entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
              }
              /*uint32_t source = pkt->ip_src;
              uint32_t target = pkt->ip_dst;
              pkt->ip_dst = source;
              pkt->ip_src = target;*/
              start_of_pckt->ether_type = htons(ethertype_ip);
              /*print_hdrs(block,ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t));*/
              sr_send_packet(sr, block, ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t), match->interface);
              free(block);
            }
            /*?
            if(sr_arpcache_lookup()){
              
            }*/

            /*if(find destination MAC addr in arp cache using dest ip){
              send modified packet immediately
            }*/
            else /*(did not contain dest IP)*/ {
              /*printf("2c3 else lookup did not contain dest ip\n");*/
              if(match->gw.s_addr == 0){
                sr_arpcache_queuereq(&sr->cache, ip->ip_dst, (uint8_t *) block, ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t), match->interface);
              }
              else{
                sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, (uint8_t *) block, ntohs(ip->ip_len) + sizeof(sr_ethernet_hdr_t), match->interface);
              }
              send_arp_req(sr, iface2, ip->ip_dst, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
              free(block);
              /*dont send modified pack
              send ARP request to out interface
              cache modified ip packet in arp request queue
              once received arp response, send all pending packets according to this dest mac addr inside queue at 1bii*/
            }      
            /*Ideally, you should find the Destination MAC Address in your ARP cache using the 
            Destination IP Address. If you can find the destination MAC address, then you can 
            just send this modified packet immediately. However, it is possible that your current
            ARP cache did not contain the information of the destination IP. In this case, you should 
            not send this modified packet since you lack the destination MAC Address. Therefore, 
            you should send an ARP request to the out interface, and cache the modified IP packet 
            in the ARP request queue. Once you received the arp response, you can send all the
              pending packets according to this destination MAC address inside the queue at 
            step 1.b.ii*/
          }
          /*LAB5 1bii*/
          else{
            /*printf("match not null but match interface down\n");*/
            icmp_unreachable(sr, Unreachable_net_code, ip, interface);
          }

        }
      }
    }
  }
}

void send_arp_req(struct sr_instance* sr, struct sr_if* iface, uint32_t ipadress, unsigned int len){
  /*int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);*/
  /*printf("am in send_arp_req\n");*/
  uint8_t *block = (uint8_t *) malloc(len);
  memset(block, 0, sizeof(uint8_t) * len);
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));

  memcpy(ethernet_hdr->ether_shost, iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memset(ethernet_hdr->ether_dhost, 0xff, sizeof(uint8_t) * ETHER_ADDR_LEN); 
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


void icmp_time(struct sr_instance * sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip, char* interface){
  /*printf("icmp time\n");*/
  uint8_t * block = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len));
  /*printf("malloc successful\n");*/

  /*ethernet header*/
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  struct sr_if * iface = sr_get_interface(sr, interface);
  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);
  /*printf("entry and iface get\n");*/

  if(entry==NULL){
    /*printf("do something!\n");*/
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  }
  else{
    memcpy(ethernet_hdr->ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
  }
  /*printf("malloced dhost\n");*/

  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  /*printf("shost\n");*/
  ethernet_hdr->ether_type = htons(ethertype_ip);
  /*printf("type\n");*/


  
  /*ip header*/

  /*printf("ip header\n");*/
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

  /*icmp header*/

  /*printf("icmp header\n");*/
  sr_icmp_t11_hdr_t* icmp_t11_hdr = (sr_icmp_t11_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_t11_hdr->icmp_type = type;
  icmp_t11_hdr->icmp_code = code;
  icmp_t11_hdr->icmp_sum = 0;
  icmp_t11_hdr->unused = Unused;
  memcpy((icmp_t11_hdr->data), (uint8_t *) ip, sizeof(uint8_t) * ICMP_DATA_SIZE);
  icmp_t11_hdr->icmp_sum = cksum((void *)icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));


  
  /*printf("sending\n");*/
  /*Send this ICMP Reply packet back to the Sender*/
  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
  /*print_hdrs((uint8_t*) block, packet_len);*/
  sr_send_packet(sr, block, packet_len, interface );
  free(block);
  /*free(ether_shost);
  free(ether_dhost);*/
  
}


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



void icmp_unreachable(struct sr_instance * sr, uint8_t code, sr_ip_hdr_t * ip, char* interface){
  
  uint8_t * block = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len));

  /*ethernet header*/
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  struct sr_if * iface = sr_get_interface(sr, interface);
  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);
  /*printf("entry and iface get\n");*/

  if(entry==NULL){
    /*printf("do something!\n");*/
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  }
  else{
    memcpy(ethernet_hdr->ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
  }
  /*printf("malloced dhost\n");*/

  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  /*printf("shost\n");*/
  ethernet_hdr->ether_type = htons(ethertype_ip);
  /*printf("type\n");*/

  
  /*ip header*/
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

  /*icmp header*/
  sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_t3_hdr->icmp_type = t3_type;
  icmp_t3_hdr->icmp_code = code;
  icmp_t3_hdr->next_mtu = Next_mtu;
  icmp_t3_hdr->icmp_sum = 0;
  icmp_t3_hdr->unused = Unused;
  memcpy((icmp_t3_hdr->data), (uint8_t *) ip, sizeof(uint8_t) * ICMP_DATA_SIZE);
  icmp_t3_hdr->icmp_sum = cksum((void *)icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));


  
  /*Send this ICMP Reply packet back to the Sender*/
  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  /*print_hdrs((uint8_t*) block, packet_len);*/
  sr_send_packet(sr, block, packet_len, interface );
  free(block);
  
}


/*2b1*/
void handle_icmp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface){
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(buf);
  sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (((void *) buf)+ sizeof(sr_ip_hdr_t));
  uint8_t type = icmp_hdr->icmp_type;
  if(type==Echorequest){
    /*2b12*/
    /*printf("is echo request\n");*/
    sr_icmp_send_message(sr, Echoreply, Echoreply, ip_hdr, interface);
  }
  /*2b11 If this is not an ICMP ECHO packet, your router can ignore this packet*/
  else{
    /*printf("ignoring packet\n");*/
  }
}

/*void fillin(struct sr_instance* sr,sr_ip_hdr_t * ip, char* interface,sr_ethernet_hdr_t * block)*/

void sr_icmp_send_message(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip, char* interface){
  /*printf("sending icmp\n");*/
  /*2b12a Malloc a space to store ethernet header and IP header and ICMP header*/
  uint8_t * block = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len));
  sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
  /*printf("filling in\n");*/
  /*fillin( sr,ip, interface,block);*/
  /*2b12d,e Fill the Source MAC Address, Destination MAC Address, Ethernet Type in ethernet header*/
  struct sr_if * iface = sr_get_interface(sr, interface);
  memcpy(ethernet_hdr->ether_shost, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
  /*printf("shost finished\n");*/

  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);
  /*printf("print2\n");*/

  if(entry==NULL){
    /*printf("do something!\n");*/
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  }
  else{
    memcpy(ethernet_hdr->ether_dhost, entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
  }
  /*printf("dhost finished\n");*/

  ethernet_hdr->ether_type = htons(ethertype_ip);

  /*struct sr_if * iface = sr_get_interface(sr, interface);
  struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), ip->ip_src);
  memcpy(block->ether_dhost, entry->mac, ETHER_ADDR_LEN);
  memcpy(block->ether_shost, iface->addr, ETHER_ADDR_LEN);
  block->ether_type = htons(ethertype_ip);
  printf("ip\n");*/
  /*2b12cFill the source IP address, destination IP address, ttl, protocol, length, checksum in IP header*/
  uint32_t ip_src = ntohl(ip->ip_dst);
  uint32_t ip_dst= ntohl(ip->ip_src);
  sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
  memcpy(pkt, ip, ntohs(ip->ip_len));
  /*pkt->ip_hl = 0x5;
  pkt->ip_v  = 0x4;
  pkt->ip_tos = iptos;
  pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t8_hdr_t)));
  pkt->ip_id = htons(ipid);
  pkt->ip_off = htons(ipoff);
  pkt->ip_ttl = ipttl;
  pkt->ip_p = ip_protocol_icmp;*/
  pkt->ip_sum = 0;
  pkt->ip_src = htonl(ip_src);
  pkt->ip_dst = htonl(ip_dst);
  pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));

  /*2b12b Fill the ICMP code, type in ICMP header*/
  sr_icmp_t8_hdr_t* icmp_hdr = (sr_icmp_t8_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  /*sr_icmp_t8_hdr_t* icmp = (sr_icmp_t8_hdr_t*)(ip+1);
  memcpy(icmp_hdr, icmp, 8);*/
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum  = 0;
  icmp_hdr->icmp_sum = cksum((void *)icmp_hdr, sizeof(sr_icmp_t8_hdr_t));

  unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip->ip_len);
  /*2b13 Send this ICMP Reply packet back to the Sender*/

  /*print_hdr_eth((uint8_t *)block);
  print_hdr_ip((uint8_t *)(block + sizeof(sr_ethernet_hdr_t) ));
  print_hdr_icmp((uint8_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
  print_hdrs((uint8_t*) block, packet_len);*/
  sr_send_packet(sr, block, packet_len, interface );
  free(block);
}


int is_own_ip(struct sr_instance* sr, sr_ip_hdr_t* current) {
  int value = 0;
	/*struct sr_rt * table = sr->routing_table;*/
	struct sr_if * iface = sr->if_list;
  /*printf("iface established\n");*/
	while (iface != NULL) {
    /*printf("not null\n");*/
		if (current->ip_dst == iface->ip && sr_obtain_interface_status(sr,iface->name)!=0) {
			return 1;
		}
    else if(current->ip_dst == iface->ip && sr_obtain_interface_status(sr,iface->name)==0) {
      value = 2;
    }
		iface = iface->next;
	}
  /*printf("is not own ip\n");*/
	if(value==2) return 2;
  return 0;
}

void sr_handle_arp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface) {
	sr_arp_hdr_t* arp = (sr_arp_hdr_t*) buf;
	enum sr_arp_opcode op = (enum sr_arp_opcode)ntohs(arp->ar_op);
	struct sr_if* iface = sr_get_interface(sr, interface);
	/*switch(op) {
		case arp_op_request: */
  if(arp_op_request==op){

    /*printf("it's an arp request\n");*/
    /* case 1a */

    /*printf("op request\n");
    print_hdrs(buf - sizeof(sr_ethernet_hdr_t), sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));*/
    struct sr_arpreq * pending = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip); /*1a1 Insert the Sender MAC in this packet to your ARP cache*/
    /* TODO: 1a2: optimization? */
    if (pending) {
      /*printf("pending is happening in request\n");*/
      struct sr_packet *current = pending->packets;
      while (current) { 
          /*printf("current\n");*/
          uint8_t *packet = current->buf;
          sr_ethernet_hdr_t *curheader = (sr_ethernet_hdr_t *)packet;
          memcpy(curheader->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
          memcpy(curheader->ether_shost, iface->addr, ETHER_ADDR_LEN);
          curheader->ether_type = htons(ethertype_ip);
          /*print_hdrs(packet,current->len);*/
          sr_send_packet(sr, packet, current->len, interface);


          current = current->next;
      }
      sr_arpreq_destroy(&(sr->cache), pending);
    }

    send_arp_rep(sr, iface, arp); /*1a3,4*/
  }
  /*case arp_op_reply:*/
  if(arp_op_reply==op){
    /* case 1b */
    /*printf("its an opreply\n");*/
    struct sr_arpreq * pending = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip); /* 1b1 Insert the Target MAC to your ARP cache*/
    /* TODO: 1b2 */
    if (pending) {
      /*printf("pending is happening in reply\n");*/
      struct sr_packet *current = pending->packets;
      while (current!=NULL) { 
          /*printf("current\n");*/
          uint8_t *packet = current->buf;
          sr_ethernet_hdr_t *curheader = (sr_ethernet_hdr_t *)packet;
          memcpy(curheader->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
          memcpy(curheader->ether_shost, iface->addr, ETHER_ADDR_LEN);
          curheader->ether_type = htons(ethertype_ip);
          /*print_hdrs(packet, current->len);*/
          sr_send_packet(sr, packet, current->len, interface);
          current = current->next;
      }
      sr_arpreq_destroy(&(sr->cache), pending);
    }
    
  
  }
}


void send_arp_rep(struct sr_instance* sr, struct sr_if* iface, sr_arp_hdr_t* arp){

  /* 1 Malloc a space to store an Ethernet header and ARP header */
  uint8_t* block = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	sr_arp_hdr_t* arphdr = (sr_arp_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* ethhdr = (sr_ethernet_hdr_t*)(block);

  /* 2 ill the ARP opcode, Sender IP, Sender MAC, Target IP, Target MAC in ARP header*/
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

  /* Send this ARP response back to the Sender */
	sr_send_packet(sr, block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), iface->name);
	free(block);
	return;
}
