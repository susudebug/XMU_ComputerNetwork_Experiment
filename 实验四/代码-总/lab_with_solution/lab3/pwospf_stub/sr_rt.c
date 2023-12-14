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


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
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

    /* -- REQUIRES -- */
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
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

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

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
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

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
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
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
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
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
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

} /* -- sr_print_routing_entry -- */


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));
        /* Fill your code here */
        
        struct sr_rt * pointer1 = sr->routing_table;
        /*For each entry in your routing table*/
        while (pointer1 != NULL) {
            /*check whether this entry has expired (Current_time – Updated_time >= 20 seconds).*/
            if(difftime(time(NULL), pointer1->updated_time) > 20){
                /*If expired, delete it from the routing table*/
                pointer1->metric = INFINITY;
            }
            pointer1=pointer1->next;
        }

        struct sr_if* interface = sr->if_list;
        /*Checking the status of the router's own interfaces*/
        while(interface!=NULL){
            /*If the status of an interface is down*/
            if(sr_obtain_interface_status(sr,interface->name)==0){
                /*printf("interface down");*/
                /*you should delete all the routing entries which use this interface to send packets*/
                struct sr_rt * pointer2 = sr->routing_table;
                while (pointer2 != NULL) {
                    if(strcmp(pointer2->interface, interface->name)==0){
                        pointer2->metric = INFINITY;
                    }
                    pointer2=pointer2->next;
                }
            }
            /*If the status of an interface is up*/
            else{
                struct sr_rt * pointer3 = sr->routing_table;
                bool found = false;
                while (pointer3 != NULL) {
                    /*you should check whether your current routing table contains the subnet 
                    this interface is directly connected to.*/

                    if((pointer3->dest.s_addr & pointer3->mask.s_addr) == (interface->ip & interface->mask) && pointer3->mask.s_addr == interface->mask){
                        /*If it contains, update the updated time. */
                        /*printf("timeout update time\n");*/
                        pointer3->updated_time = time(NULL); /*update time */
                        pointer3->metric = 0;
                        pointer3->gw.s_addr = 0;
                        strcpy(pointer3->interface, interface->name);
                        found = true;
                    }
                    pointer3 = pointer3->next;
                }
                /*Otherwise, add this subnet to your routing table*/
                if(!found){
                    struct in_addr address;
                    address.s_addr = interface->ip;
                    struct in_addr gw;
                    gw.s_addr = 0x0;
                    struct in_addr mask;
                    mask.s_addr = interface->mask;
                    /*printf("timeout add entry\n");*/
                    sr_add_rt_entry(sr,address,gw,mask,0,interface->name);
                }
            }
            interface = interface->next;
        }
        /*printf("sending rip response in timeout\n");*/
        send_rip_response(sr);     
        /*sr_print_routing_table(sr);   */
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Lab5: Fill your code here */
    
    struct sr_if* interface = sr->if_list;
    while(interface!=NULL){

        unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
        uint8_t * block = (uint8_t *) malloc(packet_len);
        memset(block, 0, sizeof(uint8_t) * packet_len);

        /*ethernet*/
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        ethernet_hdr->ether_type = htons(ethertype_ip);


        /*ip*/  
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


        /*udp*/
        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_dst = 520;
        udp_hdr->port_src = 520;
        udp_hdr->udp_len = htons((uint16_t)sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        udp_hdr->udp_sum = 0;
        udp_hdr->udp_sum = cksum(((void *) udp_hdr), sizeof(sr_udp_hdr_t));

        /*rip*/
        sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

        rip_hdr->command = 1;
        rip_hdr->version = 2;
        rip_hdr->unused = 0;
        rip_hdr->entries[0].metric = INFINITY;

        /*send*/
        sr_send_packet(sr, block, packet_len, interface->name );
        free(block);
        interface = interface->next;

    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

void send_rip_response(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Lab5: Fill your code here */

    struct sr_if* interface = sr->if_list;
    while(interface!=NULL){

        unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
        uint8_t * block = (uint8_t *) malloc(packet_len);
        memset(block, 0, sizeof(uint8_t) * packet_len);

        /*ethernet*/
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        ethernet_hdr->ether_type = htons(ethertype_ip);


        /*ip*/  
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


        /*udp*/
        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_dst = 520;
        udp_hdr->port_src = 520;
        udp_hdr->udp_len = htons((uint16_t)sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        udp_hdr->udp_sum = 0;
        udp_hdr->udp_sum = cksum(((void *) udp_hdr), sizeof(sr_udp_hdr_t));

        /*rip*/
        sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

        rip_hdr->command = 2;
        rip_hdr->version = 2;
        rip_hdr->unused = 0;

        struct sr_rt * table = sr->routing_table; 
        int i = 0;
        memset(&rip_hdr->entries,0,MAX_NUM_ENTRIES*sizeof(struct entry));
        while(table!=NULL){
            if(strcmp(table->interface, interface->name)!=0){
                rip_hdr->entries[i].afi = htons(2);
                rip_hdr->entries[i].address = table->dest.s_addr;
                rip_hdr->entries[i].mask = table->mask.s_addr;
                rip_hdr->entries[i].next_hop = table->gw.s_addr;
                rip_hdr->entries[i].metric = table->metric;
                i = i+1;
            }
            table=table->next;
        }
        /*rip_hdr->entries = e;*/
        

        /*print_hdrs(block,packet_len);*/
        /*printf("sending rip response in rip response\n");*/
        sr_send_packet(sr, block, packet_len, interface->name );
        free(block);
        interface = interface->next;

    }


    pthread_mutex_unlock(&(sr->rt_lock));
}


void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Lab5: Fill your code here */

    struct sr_if* interface = sr->if_list;
    while(interface!=NULL){

        unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t);
        uint8_t * block = (uint8_t *) malloc(packet_len);
        memset(block, 0, sizeof(uint8_t) * packet_len);

        /*ethernet*/
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)block;
        memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memset(ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        ethernet_hdr->ether_type = htons(ethertype_ip);


        /*ip*/  
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


        /*udp*/
        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_dst = 520;
        udp_hdr->port_src = 520;
        udp_hdr->udp_len = htons((uint16_t)sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        udp_hdr->udp_sum = 0;
        udp_hdr->udp_sum = cksum(((void *) udp_hdr), sizeof(sr_udp_hdr_t));

        /*rip*/
        sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t *)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

        rip_hdr->command = 2;
        rip_hdr->version = 2;
        rip_hdr->unused = 0;

        struct sr_rt * table = sr->routing_table; 
        int i = 0;
        memset(&rip_hdr->entries,0,MAX_NUM_ENTRIES*sizeof(struct entry));
        while(table!=NULL){
            if(strcmp(table->interface, interface->name)!=0){
                rip_hdr->entries[i].afi = htons(2);
                rip_hdr->entries[i].address = table->dest.s_addr;
                rip_hdr->entries[i].mask = table->mask.s_addr;
                rip_hdr->entries[i].next_hop = table->gw.s_addr;
                rip_hdr->entries[i].metric = table->metric;
                i = i+1;
            }
            table=table->next;
        }
        /*rip_hdr->entries = e;*/
        

        /*print_hdrs(block,packet_len);*/
        /*printf("sending rip response in rip response\n");*/
        sr_send_packet(sr, block, packet_len, interface->name );
        free(block);
        interface = interface->next;

    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet ,sr_rip_pkt_t* rip_packet, char* iface){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    
    pthread_mutex_unlock(&(sr->rt_lock));
}
