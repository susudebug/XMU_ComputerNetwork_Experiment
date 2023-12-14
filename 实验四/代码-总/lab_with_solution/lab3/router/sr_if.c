/*-----------------------------------------------------------------------------
 * file:  sr_inface.
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handling interfaces
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _DARWIN_
#include <sys/types.h>
#endif /* _DARWIN_ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_router.h"

/*--------------------------------------------------------------------- 
 * Method: sr_get_interface
 * Scope: Global
 *
 * Given an interface name return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(!strncmp(if_walker->name,name,sr_IFACE_NAMELEN))
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} /* -- sr_get_interface -- */

/*--------------------------------------------------------------------- 
 * Method: sr_add_interface(..)
 * Scope: Global
 *
 * Add and interface to the router's list
 *
 *---------------------------------------------------------------------*/
void sr_add_interface_status(struct sr_instance* sr, const char* name){
    struct sr_if_status_cache* if_cache_walker = 0;
    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->if_cache == 0)
    {
        sr->if_cache = (struct sr_if_status_cache*)malloc(sizeof(struct sr_if_status_cache));
        assert(sr->if_cache);
        sr->if_cache->next = 0;
        sr->if_cache->status = 1;
        strncpy(sr->if_cache->name,name,sr_IFACE_NAMELEN);
        return;
    }

    /* -- find the end of the list -- */
    if_cache_walker = sr->if_cache;
    while(if_cache_walker->next)
    {if_cache_walker = if_cache_walker->next; }

    if_cache_walker->next = (struct sr_if_status_cache*)malloc(sizeof(struct sr_if_status_cache));
    assert(if_cache_walker->next);
    if_cache_walker = if_cache_walker->next;
    strncpy(if_cache_walker->name,name,sr_IFACE_NAMELEN);
    if_cache_walker->status = 1;
    if_cache_walker->next = 0;
}

void sr_update_interface_status(struct sr_instance* sr, uint32_t status, const char* name){
    struct sr_if_status_cache* if_cache_walker = sr->if_cache;
    while (if_cache_walker){
        if (strcmp(if_cache_walker->name, name) == 0){
            if_cache_walker->status = status;
            break;
        }
        if_cache_walker = if_cache_walker->next;
    }
}

void sr_add_interface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->if_list == 0)
    {
        sr->if_list = (struct sr_if*)malloc(sizeof(struct sr_if));
        assert(sr->if_list);
        sr->if_list->next = 0;
        sr->if_list->status = 1;
        strncpy(sr->if_list->name,name,sr_IFACE_NAMELEN);
        return;
    }

    /* -- find the end of the list -- */
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    if_walker->next = (struct sr_if*)malloc(sizeof(struct sr_if));
    assert(if_walker->next);
    if_walker = if_walker->next;
    strncpy(if_walker->name,name,sr_IFACE_NAMELEN);
    if_walker->status = 1;
    if_walker->next = 0;
} /* -- sr_add_interface -- */ 

/*--------------------------------------------------------------------- 
 * Method: sr_sat_ether_addr(..)
 * Scope: Global
 *
 * set the ethernet address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_addr(struct sr_instance* sr, const unsigned char* addr)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    memcpy(if_walker->addr,addr,6);

} /* -- sr_set_ether_addr -- */

/*--------------------------------------------------------------------- 
 * Method: sr_set_ether_ip(..)
 * Scope: Global
 *
 * set the IP address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_ip(struct sr_instance* sr, uint32_t ip_nbo)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    if_walker->ip = ip_nbo;

} /* -- sr_set_ether_ip -- */


void sr_set_ether_mask(struct sr_instance* sr, uint32_t mask_nbo)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    if_walker->mask = mask_nbo;

} /* -- sr_set_ether_ip -- */



uint32_t sr_obtain_interface_status(struct sr_instance* sr, const char* name){
    struct sr_if_status_cache* if_cache_walker = sr->if_cache;
    while (if_cache_walker){
        if (strcmp(if_cache_walker->name, name) == 0){
            return if_cache_walker->status;
        }
        if_cache_walker = if_cache_walker->next;
    }
    return 0;
}

/*--------------------------------------------------------------------- 
 * Method: sr_print_if_list(..)
 * Scope: Global
 *
 * print out the list of interfaces to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if_list(struct sr_instance* sr)
{
    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
    {
        printf(" Interface list empty \n");
        return;
    }

    if_walker = sr->if_list;
    
    sr_print_if(if_walker);
    while(if_walker->next)
    {
        if_walker = if_walker->next; 
        sr_print_if(if_walker);
    }

} /* -- sr_print_if_list -- */

/*--------------------------------------------------------------------- 
 * Method: sr_print_if(..)
 * Scope: Global
 *
 * print out a single interface to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if(struct sr_if* iface)
{
    struct in_addr ip_addr;
    struct in_addr ip_mask;
    /* -- REQUIRES --*/
    assert(iface);
    assert(iface->name);

    ip_addr.s_addr = iface->ip;
    ip_mask.s_addr = iface->mask;
    Debug("%s\tHWaddr",iface->name);
    DebugMAC(iface->addr);
    Debug("\n");
    Debug("\tinet addr %s\n",inet_ntoa(ip_addr));
    Debug("\tinet mask %s\n",inet_ntoa(ip_mask));
} /* -- sr_print_if -- */
