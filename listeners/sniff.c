/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: sniff.c,v 1.2 2004/04/13 09:15:02 flagz Exp $
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>

#include "listener.h"

#ifdef EXTENDED_INFOS
#define extprintf(...)	printf(__VA_ARGS__)
#else
#define extprintf(...)
#endif


// return link header length
int get_linkhdr_len(pcap_t *pfp) {
	switch (pcap_datalink(pfp)) {
		case DLT_EN10MB: {
			return 14;
			break;
		}
		default: {
			printf("linkhdr_len: Cannot recognize link-header length, using ethernet\n");
			return 14;
		}
	}
}

// sniff main loop
void sniff_main(struct listenparams *p) {
	pcap_t *pcapfp;
	// struct bpf_program bpfp;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned long long int n_pkt = 0;
	int linkhdr_len;
	/* FIXME: Add check if ipsrc or ipdst is TARGETMACHINE */
        // char filter[] = "tcp and (port 139 or port 445)"; // this will change to catch more than only smb transfers
	
	struct pcap_pkthdr hdr;
	unsigned char *pkt;
	struct IpHdr *ip;
	struct pcap_stat ps;
	double x,curtime;
	struct packet *pk;
	
	if (p->online_mode) {
		printf("Sniffing directly on device %s...\n",p->ifname);
		pcapfp = pcap_open_live(p->ifname, PKTMAX, 1, 0, errbuf);
	}
	else {
		printf("Reading sniffed data in file %s \n",p->ifname);
		pcapfp = pcap_open_offline(p->ifname, errbuf);
	}

	if (pcapfp == NULL) {
		fprintf(stderr, "Error opening libpcap: %s\n",
				errbuf);
		exit(1);
	}
	
	/*
	if (pcap_compile(pcapfp, &bpfp, filter, 0, 0) == -1) {
		fprintf(stderr, "Error compiling the BPF program: %s\n",
				pcap_geterr(pcapfp));
		exit(1);
	}
	if (pcap_setfilter(pcapfp, &bpfp) == -1) {
		fprintf(stderr, "pcap_setfilter: %s\n",
				pcap_geterr(pcapfp));
		exit(1);
	}
	pcap_freecode(&bpfp);
	*/

	linkhdr_len = get_linkhdr_len(pcapfp);
	
	/* Start the infinite loop that read packets */
	while(1) {
		pkt = (unsigned char*) pcap_next(pcapfp, &hdr);
		if (pkt == NULL)
			continue;
		
		n_pkt++;	
		
		// only full-captured packet
		if (hdr.caplen != hdr.len) {
			printf("Skipping half-captured packet...\n");
			continue;
		}
		
		if (pcap_stats(pcapfp, &ps) == 0)
			extprintf("%lld)STATS-->PKT RECEIVED:%d, PKT DROPPED: %d\n",n_pkt,ps.ps_recv,ps.ps_drop);

		
		ip = (unsigned char*) (pkt+linkhdr_len);

		x = (double) hdr.ts.tv_usec;
		while (x > 1) {
			x /= 10;
		}
		curtime = (double)(x+hdr.ts.tv_sec);
		
		//make a struct pkt_list to append to the queue
		pk = (struct packet *)malloc(sizeof(struct packet));
		if (pk == NULL) {
			perror("malloc");
			exit(5);
		}
		pk->n_pkt = n_pkt;
		pk->curtime = curtime;
		memcpy(pk->pkt,ip,IPMAX);
		
		pktqueue_append(pk);
		
		//if (!p->online_mode)
		//	pthread_yield();
	}
	/* not reached */
	pcap_close(pcapfp);
}
