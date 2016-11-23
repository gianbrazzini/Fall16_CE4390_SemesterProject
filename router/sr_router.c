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
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
	unsigned int orig_len, struct sr_if *src_iface)
{
	/* Allocate space for packet */
	unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
	if (NULL == reply_pkt)
	{
		fprintf(stderr, "Failed to allocate space for ARP reply");
		return;
	}

	sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
	sr_arp_hdr_t *orig_arphdr =
		(sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

	sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
	sr_arp_hdr_t *reply_arphdr =
		(sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

	/* Populate Ethernet header */
	memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
	reply_ethhdr->ether_type = orig_ethhdr->ether_type;

	/* Populate ARP header */
	memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
	reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
	reply_arphdr->ar_pro = orig_arphdr->ar_pro;
	reply_arphdr->ar_hln = orig_arphdr->ar_hln;
	reply_arphdr->ar_pln = orig_arphdr->ar_pln;
	reply_arphdr->ar_op = htons(arp_op_reply);
	memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
	reply_arphdr->ar_tip = orig_arphdr->ar_sip;
	memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
	reply_arphdr->ar_sip = src_iface->ip;

	/* Send ARP reply */
	printf("Send ARP reply\n");
	print_hdrs(reply_pkt, reply_len);
	sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
	free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr,
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
	struct sr_if *out_iface)
{
	/* Allocate space for ARP request packet */
	unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
	if (NULL == reqst_pkt)
	{
		fprintf(stderr, "Failed to allocate space for ARP reply");
		return;
	}

	sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
	sr_arp_hdr_t *reqst_arphdr =
		(sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

	/* Populate Ethernet header */
	memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
	memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
	reqst_ethhdr->ether_type = htons(ethertype_arp);

	/* Populate ARP header */
	reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
	reqst_arphdr->ar_pro = htons(ethertype_ip);
	reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
	reqst_arphdr->ar_pln = sizeof(uint32_t);
	reqst_arphdr->ar_op = htons(arp_op_request);
	memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
	reqst_arphdr->ar_sip = out_iface->ip;
	memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
	reqst_arphdr->ar_tip = req->ip;

	/* Send ARP request */
	printf("Send ARP request\n");
	print_hdrs(reqst_pkt, reqst_len);
	sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
	free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr,
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or
 * or generate an ARP request packet
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
	struct sr_if *out_iface)
{
	time_t now = time(NULL);
	if (difftime(now, req->sent) >= 1.0)
	{
		if (req->times_sent >= 5)
		{
			/*********************************************************************/
			/* TODO: send ICMP host unreachable to the source address of all     */
			/* packets waiting on this request                                   */
			printf("Sending ICMP host unreachable\n");
			struct sr_packet* current_packet;
			current_packet = req->packets;
			while (current_packet)
			{
				sr_send_icmp(sr, current_packet->buf, current_packet->len, ICMP_UNREACHABLE_TYPE, ICMP_HOST_CODE);
				current_packet = current_packet->next;
			}
			/*********************************************************************/
			sr_arpreq_destroy(&(sr->cache), req);
		}
		else
		{
			printf("No response, send request\n");

			/* Send ARP request packet */
			sr_send_arprequest(sr, req, out_iface);

			/* Update ARP request entry to indicate ARP request packet was sent */
			req->sent = now;
			req->times_sent++;
		}
	}
} /* -- sr_handle_arpreq -- */

/*PATRICK*/
void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
	struct sr_rt *rt;
	struct sr_if *interface;
	sr_icmp_hdr_t icmp_header;
	sr_icmp_hdr_t *icmp_header_ptr;
	sr_ip_hdr_t ip_header;
	sr_ip_hdr_t *error_ip_header_ptr;
	uint32_t ip_dst;

	uint16_t icmp_len;
	uint16_t total_len;
	uint8_t *new_ip_packet;
	uint8_t *new_ip_packet_ptr;

	if (type == ICMP_UNREACHABLE_TYPE)
	{
		rt = sr_longest_prefix_match(sr, convert_to_in_addr(error_ip_header_ptr->ip_src));
		if (!rt)
		{
			printf("IP source not reachable");
			return;
		}

		sr_get_interface(sr, rt->interface);
		icmp_header.icmp_type = type;
		icmp_header.icmp_code = code;
		icmp_header.icmp_sum = 0;

		ip_header.ip_hl = 5;
		ip_header.ip_v = 4;
		ip_header.ip_tos = 0;
		ip_header.ip_len = 0;
		ip_header.ip_id = error_ip_header_ptr->ip_id;
		ip_header.ip_off = htons(IP_DF);
		ip_header.ip_ttl = 64;
		ip_header.ip_p = ip_protocol_icmp;
		ip_header.ip_sum = 0;
		ip_header.ip_src = interface->ip;
		ip_header.ip_dst = error_ip_header_ptr->ip_src;
		ip_dst = ip_header.ip_dst;

		icmp_len = sizeof(icmp_header) + get_ip_header_len(error_ip_header_ptr) + 8;
		total_len = icmp_len + 20;
		ip_header.ip_len = htons(total_len);

		ip_header.ip_sum = cksum(&ip_header, 20);

		new_ip_packet = malloc(total_len);
		new_ip_packet_ptr = new_ip_packet;

		memcpy(new_ip_packet_ptr, &ip_header, 20);
		new_ip_packet_ptr += 20;

		memcpy(new_ip_packet_ptr, &icmp_header, sizeof(icmp_header));
		new_ip_packet_ptr += sizeof(icmp_header);

		memcpy(new_ip_packet_ptr, error_ip_header_ptr, get_ip_header_len(error_ip_header_ptr) + 8);

		icmp_header_ptr = get_icmp_header((sr_ip_hdr_t*)new_ip_packet);
		icmp_header_ptr->icmp_sum = cksum(icmp_header_ptr, icmp_len);

		sr_send_eth(sr, new_ip_packet, total_len, ip_dst, ethertype_ip, 0);
		free(new_ip_packet);
	}
}

/*PATRICK*/
void sr_send_eth(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint32_t ip_dst, uint16_t type, int send_icmp)
{
	struct sr_rt *rt;
	struct sr_if *interface;
	struct sr_arpentry *arp_entry;
	unsigned int eth_packet_len;
	uint8_t *eth_packet;
	sr_ethernet_hdr_t eth_header;
	struct sr_arpreq *arp_req;

	rt = sr_longest_prefix_match(sr, convert_to_in_addr(ip_dst));
	if (!rt)
	{
		printf("Cannot find routing entry\n");
		if (send_icmp)
		{
			sr_send_icmp(sr, packet, len, ICMP_UNREACHABLE_TYPE, ICMP_NET_CODE);
		}
		return;
	}

	printf("Routing entry found\n");
	interface = sr_get_interface(sr, rt->interface);

	printf("Looking for arp entry\n");
	arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
	if (arp_entry || type == ethertype_arp)
	{
		printf("Arp entry found\n");
		eth_packet_len = len + sizeof(eth_header);
		eth_header.ether_type = htons(type);
		if (type == ethertype_arp && get_arp_op((sr_arp_hdr_t*)packet) == arp_op_request)
		{
			memset(eth_header.ether_dhost, 0xFF, ETHER_ADDR_LEN);
		}
		else
		{
			memcpy(eth_header.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
		}
		memcpy(eth_header.ether_shost, interface->addr, ETHER_ADDR_LEN);
		eth_packet = malloc(eth_packet_len);
		memcpy(eth_packet, &eth_header, sizeof(eth_header));
		memcpy(eth_packet + sizeof(eth_header), packet, len);

		printf("Sending the packet\n");
		sr_send_packet(sr, eth_packet, eth_packet_len, rt->interface);
		free(eth_packet);
		if (arp_entry)
		{
			free(arp_entry);
		}
	}
	else
	{
		printf("No arp entry found\n");
		eth_packet = malloc(len);
		memcpy(eth_packet, packet, len);
		printf("Send arp request\n");
		arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_packet, len, rt->interface);
		sr_handle_arpreq(sr, arp_req, interface);
		free(eth_packet);
	}
}

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip,
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
	unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
	struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip,
		pkt, len, out_iface->name);
	sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
	unsigned int len, struct sr_if *src_iface)
{
	/* Drop packet if it is less than the size of Ethernet and ARP headers */
	if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
	{
		printf("Packet is too short => drop packet\n");
		return;
	}

	sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

	switch (ntohs(arphdr->ar_op))
	{
	case arp_op_request:
	{
		/* Check if request is for one of my interfaces */
		if (arphdr->ar_tip == src_iface->ip)
		{
			sr_send_arpreply(sr, pkt, len, src_iface);
		}
		break;
	}
	case arp_op_reply:
	{
		/* Check if reply is for one of my interfaces */
		if (arphdr->ar_tip != src_iface->ip)
		{
			break;
		}

		/* Update ARP cache with contents of ARP reply */
		struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha,
			arphdr->ar_sip);

		/* Process pending ARP request entry, if there is one */
		if (req != NULL)
		{
			/*********************************************************************/
			/* TODO: send all packets on the req->packets linked list            */

			/*********************************************************************/

			/* Release ARP request entry */
			sr_arpreq_destroy(&(sr->cache), req);
		}
		break;
	}
	default:
		printf("Unknown ARP opcode => drop packet\n");
		return;
	}
} /* -- sr_handlepacket_arp -- */

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

	printf("*** -> Received packet of length %d \n", len);

	/*************************************************************************/
	/* TODO: Handle packets                                                  */

	/*************************************************************************/
}/* end sr_ForwardPacket */
