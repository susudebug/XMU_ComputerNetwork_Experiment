/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method: sr_load_rt() 
 * @brief function loads routing table entries from a file 
 * @param sr: pointer to simple router state.
 * @param filename: the file name where the routing entries stores 
 * @return: 0 success
 *          -1 otherwise
 *---------------------------------------------------------------------*/
int sr_load_rt(struct sr_instance* sr,const char* filename)
{
  FILE* fp;
  char  line[BUFSIZ];
  char  dest[32];
  char  gw[32];
  char  mask[32];    
  char  iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;
  int clear_routing_table = 0;

  assert(filename);
  if( access(filename,R_OK) != 0)
  {
    perror("access");
    return -1;
  }

  fp = fopen(filename,"r");

  while( fgets(line,BUFSIZ,fp) != 0)
  {
    sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
    if(inet_aton(dest,&dest_addr) == 0)
    { 
      fprintf(stderr,
          "Error loading routing table, cannot convert %s to valid IP\n",
          dest);
      return -1; 
    }
    if(inet_aton(gw,&gw_addr) == 0)
    { 
      fprintf(stderr,
          "Error loading routing table, cannot convert %s to valid IP\n",
          gw);
      return -1; 
    }
    if(inet_aton(mask,&mask_addr) == 0)
    { 
      fprintf(stderr,
          "Error loading routing table, cannot convert %s to valid IP\n",
          mask);
      return -1; 
    }
    if( clear_routing_table == 0 ){
      printf("Loading routing table from server, clear local routing table.\n");
      sr->routing_table = 0;
      clear_routing_table = 1;
    }
    sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
  } 

  return 0; 
} 

/*---------------------------------------------------------------------
 * Method: sr_build_rt() 
 * @brief function creates routing table entries where the destination ip is the
 * router's ip
 * @param sr: pointer to simple router state.
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
  struct sr_if* interface = sr->if_list;
  char  iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;
  /* Add routing entries that the destination IP is the router's own IP */
  while (interface){
    dest_addr.s_addr = (interface->ip & interface->mask);
    gw_addr.s_addr = 0;
    mask_addr.s_addr = interface->mask;
    strcpy(iface, interface->name);
    sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
    interface = interface->next;
  }
  return 0;
}


/*---------------------------------------------------------------------
 * Method: sr_add_rt_entry() 
 * @brief function adds a specified routing table entry   
 * @param sr: pointer to simple router state.
 * @param dest: destination ip
 * @param gw: the next hop ip
 * @param mask: network mask
 * @param metric: distance
 * @param if_name: name of the forwarding interface 
 *---------------------------------------------------------------------*/
void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
    struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
  struct sr_rt* rt_walker = 0;

  assert(if_name);
  assert(sr);

  pthread_mutex_lock(&(sr->rt_locker));
  /* 1. If the routing table is empty, directly add the entry */
  if(sr->routing_table == 0)
  {
    sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(sr->routing_table);
    sr->routing_table->next = 0;
    sr->routing_table->dest = dest;
    sr->routing_table->gw   = gw;
    sr->routing_table->mask = mask;
    strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
    sr->routing_table->metric = metric;
    time_t now;
    time(&now);
    sr->routing_table->updated_time = now;

    pthread_mutex_unlock(&(sr->rt_locker));
    return;
  }

  /* 2. If there already exist some entries in the routing table, find the end of the table first  -- */
  rt_walker = sr->routing_table;
  while(rt_walker->next){
    rt_walker = rt_walker->next; 
  }

  rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
  assert(rt_walker->next);
  rt_walker = rt_walker->next;
  rt_walker->next = 0;
  rt_walker->dest = dest;
  rt_walker->gw   = gw;
  rt_walker->mask = mask;
  strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
  rt_walker->metric = metric;
  time_t now;
  time(&now);
  rt_walker->updated_time = now;

  pthread_mutex_unlock(&(sr->rt_locker));
} 

/*---------------------------------------------------------------------
 * Method: sr_print_routing_table() 
 * @brief function print all entries in the routing table.
 * @param sr: pointer to simple router state.
 *---------------------------------------------------------------------*/
void sr_print_routing_table(struct sr_instance* sr)
{
  pthread_mutex_lock(&(sr->rt_locker));
  struct sr_rt* rt_walker = 0;

  if(sr->routing_table == 0)
  {
    printf(" *warning* Routing table empty \n");
    pthread_mutex_unlock(&(sr->rt_locker));
    return;
  }
  printf("  <---------- Router Table ---------->\n");
  printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

  rt_walker = sr->routing_table;

  while(rt_walker){
    if (rt_walker->metric < INFINITY)
      sr_print_routing_entry(rt_walker);
    rt_walker = rt_walker->next;
  }
  pthread_mutex_unlock(&(sr->rt_locker));


} 

/*---------------------------------------------------------------------
 * Method: sr_print_routing_entry() 
 * @brief function print the specified entries in the routing table.
 * @param entry: pointer to the routing entry.
 *---------------------------------------------------------------------*/
void sr_print_routing_entry(struct sr_rt* entry)
{
  assert(entry);
  assert(entry->interface);

  char buff[20];
  struct tm* timenow = localtime(&(entry->updated_time));
  strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
  printf("%s\t",inet_ntoa(entry->dest));
  printf("%s\t",inet_ntoa(entry->gw));
  printf("%s\t",inet_ntoa(entry->mask));
  printf("%s\t",entry->interface);
  printf("%d\t",entry->metric);
  printf("%s\n", buff);

} 

/*---------------------------------------------------------------------
 * Method: sr_rip_timeout() 
 * @brief function periodically checks the status of all interfaces and updates the routing table   
 * @param sr_ptr: pointer to simple router state.
 *---------------------------------------------------------------------*/
void *sr_rip_timeout(void *sr_ptr) {
  struct sr_instance *sr = sr_ptr;
  while (1) {
    /* 1 update the routing table and send RIP response message to neighbors every 5 seconds */
    sleep(5);
    pthread_mutex_lock(&(sr->rt_locker));

    struct sr_rt * pointer1 = sr->routing_table;
    /* 2 For each entry in your routing table*/
    while (pointer1 != NULL) {
      /* 2.a check whether this entry has expired (Current_time – Updated_time >= 20 seconds).*/
      if(difftime(time(NULL), pointer1->updated_time) > 20){
        /* 2.b If expired, delete it from the routing table*/
        pointer1->metric = INFINITY;
      }
      pointer1=pointer1->next;
    }

    struct sr_if* interface = sr->if_list;
    /* 3 Checking the status of the router's own interfaces*/
    while(interface!=NULL){
      /* 3.a If the status of an interface is down*/
      /*you should delete all the routing entries which use this interface to send packets*/
      if(sr_obtain_interface_status(sr,interface->name)==0){
        struct sr_rt * pointer2 = sr->routing_table;
        while (pointer2 != NULL) {
          if(strcmp(pointer2->interface, interface->name)==0){
            pointer2->metric = INFINITY;
          }
          pointer2=pointer2->next;
        }
      }
      /* 3.b If the status of an interface is up*/
      /* you should check whether your current routing table contains the subnet this interface is directly connected to.*/
      else{
        struct sr_rt * pointer3 = sr->routing_table;
        bool found = false;
        while (pointer3 != NULL) {
          /* 3.b.1 If it contains, update the updated time, metric, gateway, and interface in the routing entry*/
          if((pointer3->dest.s_addr & pointer3->mask.s_addr) == (interface->ip & interface->mask) && pointer3->mask.s_addr == interface->mask){
            /* Lab4-Task3 TODO */
            pointer3->updated_time = time(NULL); /*update time */
            pointer3->metric = 0;
            pointer3->gw.s_addr = 0;
            strcpy(pointer3->interface, interface->name);
            /* End TODO */
            found = true;
          }
          pointer3 = pointer3->next;
        }
        /* 3.b.2 Otherwise, add this subnet to your routing table*/
        if(!found){
          struct in_addr address;
          address.s_addr = interface->ip;
          struct in_addr gw;
          gw.s_addr = 0x0;
          struct in_addr mask;
          mask.s_addr = interface->mask;
          sr_add_rt_entry(sr,address,gw,mask,0,interface->name);
        }
      }
      interface = interface->next;
    }
    /* 4 Send RIP response in timeout */
    send_rip_response(sr);     
    sr_print_routing_table(sr);   
    pthread_mutex_unlock(&(sr->rt_locker));
  }
  return NULL;
}

/*---------------------------------------------------------------------
 * Method: send_rip_request() 
 * @brief function send RIP request to all its neighbors    
 * @param sr: pointer to simple router state.
 *---------------------------------------------------------------------*/
void send_rip_request(struct sr_instance *sr){
  pthread_mutex_lock(&(sr->rt_locker));

  struct sr_if* interface = sr->if_list;
  /*1 Send RIP request to every interface(i.e., neighbor)*/
  while(interface!=NULL){

    unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
    uint8_t * block = (uint8_t *) malloc(packet_len);
    memset(block, 0, sizeof(uint8_t) * packet_len);

    /* 1.a Set Ethernet header */
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
    /* Lab4-Task3 TODO: set source and destination MAC addresses */ 
    memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    /* End TODO */ 
    ethernet_hdr->ether_type = htons(ethertype_ip);


    /* 1.b Set IP header */  
    sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
    pkt->ip_hl = 0x5;
    pkt->ip_v  = 0x4;
    pkt->ip_tos = iptos;
    pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t)));
    pkt->ip_id = htons(ipid);
    pkt->ip_off = htons(ipoff);
    pkt->ip_ttl = ipttl;
    
    /* Lab4-Task3 TODO: set protocol in the IP header */ 
    pkt->ip_p = ip_protocol_udp;
    /* End TODO */ 
    
    pkt->ip_sum = 0;
    pkt->ip_src = interface->ip;
    
    /* Lab4-Task3 TODO: set destination ip address in the IP header */ 
    pkt->ip_dst = htonl(broadcast_ip);
    /* End TODO */ 
    
    pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));


    /*1.c Set UDP header*/
    sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    udp_hdr->port_dst = 520;
    udp_hdr->port_src = 520;
    udp_hdr->udp_len = htons((uint16_t)sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
    udp_hdr->udp_sum = 0;
    udp_hdr->udp_sum = cksum(((void *) udp_hdr), sizeof(sr_udp_hdr_t));

    /*1.d Set RIP header*/
    sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    rip_hdr->command = 1;
    rip_hdr->version = 2;
    rip_hdr->unused = 0;
    rip_hdr->entries[0].metric = INFINITY;

    /*1.e Send the request*/
    sr_send_packet(sr, block, packet_len, interface->name );
    free(block);
    interface = interface->next;
  }
  pthread_mutex_unlock(&(sr->rt_locker));
}

/*---------------------------------------------------------------------
 * Method: send_rip_request() 
 * @brief function send RIP request to all its neighbors    
 * @param sr: pointer to simple router state.
 *---------------------------------------------------------------------*/
void send_rip_response(struct sr_instance *sr){
  pthread_mutex_lock(&(sr->rt_locker));

  struct sr_if* interface = sr->if_list;
  /* 1 Send response to every interface (i.e., neighbor)*/
  while(interface!=NULL){
    unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
    uint8_t * block = (uint8_t *) malloc(packet_len);
    memset(block, 0, sizeof(uint8_t) * packet_len);

    /*1.a Set Ethernet header*/
    /* Lab4-Task3 TODO */
    /* Hint: You can refer to the header setting in send_rip_request() function  */
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
    memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    ethernet_hdr->ether_type = htons(ethertype_ip);
    /* End TODO */

    /*1.b Set IP header*/  
    /* Lab4-Task3 TODO */ 
    sr_ip_hdr_t* pkt = (sr_ip_hdr_t *)(block + sizeof(sr_ethernet_hdr_t));
    pkt->ip_hl = 0x5;
    pkt->ip_v  = 0x4;
    pkt->ip_tos = iptos;
    pkt->ip_len = htons((uint16_t) (sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t)));
    pkt->ip_id = htons(ipid);
    pkt->ip_off = htons(ipoff);
    pkt->ip_ttl = ipttl;
    pkt->ip_p = ip_protocol_udp;
    pkt->ip_sum = 0;
    pkt->ip_src = interface->ip;
    pkt->ip_dst = htonl(broadcast_ip);
    pkt->ip_sum = cksum(((void *) pkt), sizeof(sr_ip_hdr_t));
    /* End TODO */


    /*1.c Set UDP header*/
    /* Lab4-Task3 TODO */ 
    sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    udp_hdr->port_dst = 520;
    udp_hdr->port_src = 520;
    udp_hdr->udp_len = htons((uint16_t)sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
    udp_hdr->udp_sum = 0;
    udp_hdr->udp_sum = cksum(((void *) udp_hdr), sizeof(sr_udp_hdr_t));
    /* End TODO */

    /*1.d Set RIP header*/
    /* Lab4-Task3 TODO */ 
    sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    rip_hdr->command = 2;
    rip_hdr->version = 2;
    rip_hdr->unused = 0;
    /* End TODO */
    
    struct sr_rt * table = sr->routing_table; 
    int i = 0;
    memset(&rip_hdr->entries,0,MAX_NUM_ENTRIES*sizeof(struct entry));
    while(table!=NULL){
      if(strcmp(table->interface, interface->name)!=0){
        rip_hdr->entries[i].afi = htons(2);
        /* Lab4-Task3 TODO */
        /*You need to assign values to the fields in the RIP header, e.g., address, mask, next_hop and metric*/
        rip_hdr->entries[i].address = table->dest.s_addr;
        rip_hdr->entries[i].mask = table->mask.s_addr;
        rip_hdr->entries[i].next_hop = table->gw.s_addr;
        rip_hdr->entries[i].metric = table->metric;
        /* End TODO */
        i = i+1;
      }
      table=table->next;
    }


    /*2 Send RIP response*/
    sr_send_packet(sr, block, packet_len, interface->name );
    free(block);
    interface = interface->next;

  }

  pthread_mutex_unlock(&(sr->rt_locker));
}

/*---------------------------------------------------------------------
 * Method: update_route_table() 
 * @brief function update the routing table based on the received routing entries from neighbors    
 * @param sr: pointer to simple router state.
 * @param packet: received RIP response packet.
 * @param len: length of the packet
 * @param interface: interface that receives the RIP response 
 *---------------------------------------------------------------------*/
void update_route_table(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
  pthread_mutex_lock(&(sr->rt_locker));
  sr_rip_pkt_t *rip = (sr_rip_pkt_t *) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t));    
  sr_ip_hdr_t *ip = (sr_ip_hdr_t *) (packet+sizeof(sr_ethernet_hdr_t));

  int i = 0;
  /*flag to identify whether the routing entry is updated*/
  bool changed = false; 
  /*1 For each routing entry in the RIP response packet*/
  for(i = 0; i<MAX_NUM_ENTRIES; i++){
    struct entry e = rip->entries[i];
    /* 1.a If it is valid*/
    if(e.afi!=0){
      /* 1.b obtain the metric = MIN(received_metric+1, INFINITY),*/
      /* Lab4-Task3 TODO */
      e.metric = (e.metric+1< INFINITY) ? (e.metric+1) : (INFINITY);
      /* End TODO */
      struct sr_rt * table = sr->routing_table;
      bool found = false;
      /* 1.c then check whether your routing table contains this routing entry*/
      while(table!=NULL){
        /* 1.c.1 if contains this routing entry already.*/
        if((e.address & e.mask) == (table->dest.s_addr & table->mask.s_addr)){
          /*1.c.1.i If it has this entry, check if the packet is from the same router as the existing entry*/
          if(strcmp(table->interface,interface)==0){
            /*1.c.1.i(1) If true, update the updating time to the new one*/
            table->updated_time = time(0);
            
            /*1.c.1.i(2) If metric == INFINITY or if metric < current metric in routing table, update the metric and set changed as true */
            /* Lab4-Task3 TODO */ 
            if(e.metric==INFINITY && table->metric!=INFINITY){
              changed = true;
              table->metric=INFINITY;
            }

            if(e.metric < table->metric){
              changed = true;			
              table->metric = e.metric; 			
            }
            /* End TODO */
          }
          /*1.c.1.ii If it has this entry, but not from the same router */
          else{
            /* Lab4-Task3 TODO */
            /*If metric < current metric in routing table*/
            /*updating all the information in the routing entry, e.g., destination address, metric, update time, gateway, mask and interface*/
            if(e.metric < table->metric){    
              changed = true;
              table->dest.s_addr = e.address;
              table->metric = e.metric;
              table->updated_time  = time(0);
              table->mask.s_addr = e.mask;
              table->gw.s_addr = ip->ip_src;
              memcpy(table->interface, interface, sizeof(unsigned char) * sr_IFACE_NAMELEN);
            }
            /* End TODO */

          }
          found=true;
          break;
        }
        table = table->next;
      }
      /*1.c.2 If not found the entry in current routing table*/
      if(!found){
        /* Lab4-Task3 TODO */
        /*Add this routing entry to your routing table*/
        /*Hint: you can use sr_add_rt_entry() function to add an entry in the routing table*/
        changed = true;
        struct in_addr address;
        address.s_addr = e.address;
        struct in_addr gw;
        gw.s_addr = ip->ip_src;
        struct in_addr mask;
        mask.s_addr = e.mask;
        sr_add_rt_entry(sr, address,gw, mask, e.metric, interface);
        /*End TODO*/
      }
    }
  }
  /*2 Send RIP response through all interfaces if your routing table has changed (trigger updates).*/
  if(changed){
    /* Lab4-Task3 TODO */
    send_rip_response(sr);
    /* End TODO */
  }

  pthread_mutex_unlock(&(sr->rt_locker));
}
