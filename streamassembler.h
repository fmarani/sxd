/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: streamassembler.h,v 1.3 2004/04/13 09:15:02 flagz Exp $
 */ 
 

#ifndef _STREAMASSEMBLER_H
#define _STREAMASSEMBLER_H

#include <stdlib.h>
#include "streamstructs.h"

#define MAX_STREAMS	1000

#define TCP_SYN		0x0002
#define TCP_SYNACK	0x0012
#define TCP_ACK		0x0010
#define TCP_FINACK	0x0011
#define TCP_FIN		0x0001
#define TCP_RSTACK	0x0014
#define TCP_RST		0x0004

enum direction {SRC_TO_DST, DST_TO_SRC};
enum syncstate {SYNC, NOTSYNC};


#define N_FILTERS	1
// filter function prototypes...

// SMB func prototypes
int checkport(u_int32_t ipsrc, u_int32_t ipdst, u_int16_t portsrc, u_int16_t portdst, void *payload, int payloadlen);
void manage_nb(void *payload, int payloadlen, enum direction dir, enum syncstate syn, void **filterdata);
// end SMB.


// end prototypes


extern struct filter filters[N_FILTERS];


struct filter {
	char name[20];
	void (*pktin)(void *payload, int payloadlen, enum direction dir, enum syncstate syn, void **filterdata);
	int (*isInteresting)(u_int32_t ipsrc, u_int32_t ipdst, u_int16_t portsrc, u_int16_t portdst, void *payload, int payloadlen);
};

struct stream {
	u_int32_t ipsrc;
	u_int32_t ipdst;
	enum {TCP, UDP} type;
	u_int16_t portsrc;
	u_int16_t portdst;
	enum direction lastdirection;
	double time_lastpkt_src;
	double time_lastpkt_dst;
	long int n_pkt;
	
	enum {INTERESTING, INDIFFERENT, NOTINTERESTING} filterstate;
	
	// TCP DATA
	enum {STATUS_SYNCRONIZING, STATUS_OK} streamstate; 
	u_int16_t lastpayloadlen;
	u_int32_t lastseqnumber;
	u_int32_t lastacknumber;

	void *filterdata;
	union {
	struct filter *activefilter;
	struct filter *filterlist[N_FILTERS];
	} filt;
};



int stream_n_connections();
void stream_managepkt(struct IpHdr *ip, unsigned long long int n_pkt, double curtime);
void stream_init();
void filter_init();

#endif /* _STREAMASSEMBLER_H */


