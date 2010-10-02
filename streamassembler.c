/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: streamassembler.c,v 1.4 2004/04/13 09:15:02 flagz Exp $
 */ 



#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#include "streamassembler.h"
#include "streamstructs.h"
#include "common.h"
#include "list-queue.h"



#ifdef EXTENDED_INFOS
#define extprintf(...)	printf(__VA_ARGS__)
#else
#define extprintf(...)
#endif


DECLARE_LIST(streamlist);


struct filter filters[N_FILTERS];

void filter_init() {
	strcpy(filters[0].name,"SMB");
	filters[0].pktin = manage_nb;
	filters[0].isInteresting = checkport;

	// Other filter initialization here...
}

void stream_init() {
	list_init(&streamlist);
}


void tcp_addconnection(u_int32_t srcip, u_int32_t dstip, u_int16_t srcport, u_int16_t dstport, u_int32_t seqnumber, double curtime) {
	struct stream *newconn;
	char sa[64], da[64];
	int i;

	#if MAX_STREAMS > 0
	if (streamlist.list_len >= MAX_STREAMS) {
		printf("tcp_addconnection: Reached limit of streams\n");
		return;
	}
	#endif
		
	if ( (newconn = (struct stream *)malloc(sizeof(struct stream))) == NULL ) {
		printf("tcp_addconnection: Cannot allocate memory for a new connection...won't be sniffed..\n");
		return;
	}
	
	newconn->ipsrc = srcip;
	newconn->ipdst = dstip;
	newconn->type = TCP;
	newconn->portsrc = srcport;
	newconn->portdst = dstport;
	newconn->lastdirection = SRC_TO_DST;
	newconn->time_lastpkt_src = curtime;
	
	newconn->n_pkt = 1;
	
	newconn->filterstate = INDIFFERENT;
	
	newconn->streamstate = STATUS_SYNCRONIZING;
	newconn->lastpayloadlen = 0;
	newconn->lastseqnumber = seqnumber;

	newconn->filterdata = NULL;
	
	for (i=0; i<N_FILTERS; i++) {
		newconn->filt.filterlist[i] = filters+i;
	}
	
	printf("tcp_addconnection: Connection from %s:%d to %s:%d (SYN)\n", ipv4addr_tostr(sa, &srcip), srcport, ipv4addr_tostr(da, &dstip), dstport);
	list_append(&streamlist,newconn);
}


struct tcp_list_sync_data {
	u_int32_t ipsrc;
	u_int32_t ipdst;
	u_int16_t portsrc;
	u_int16_t portdst;
	u_int32_t acknumber;
};
int tcp_list_sync_compare(void *data, void *confirm) {
	struct tcp_list_sync_data *confirmdata = (struct tcp_list_sync_data *)confirm;
	struct stream *streamdata = (struct stream *)data;
	if (	streamdata->ipdst == confirmdata->ipsrc &&
		streamdata->ipsrc == confirmdata->ipdst &&
		streamdata->portdst == confirmdata->portsrc &&
		streamdata->portsrc == confirmdata->portdst &&
		streamdata->type == TCP &&
		streamdata->lastdirection == SRC_TO_DST &&
		streamdata->streamstate == STATUS_SYNCRONIZING &&
		streamdata->lastseqnumber + 1 == confirmdata->acknumber)
		return 1;
	return 0;
}

void tcp_confirmconn(u_int32_t srcip, u_int32_t dstip, u_int16_t srcport, u_int16_t dstport, u_int32_t seqnumber, u_int32_t acknumber, double curtime) {
	struct stream *s;
	char sa[64], da[64];
	struct tcp_list_sync_data confirm;

	confirm.ipsrc = srcip;
	confirm.ipdst = dstip;
	confirm.portsrc = srcport;
	confirm.portdst = dstport;
	confirm.acknumber = acknumber;
	
	if ( s = (struct stream *) list_find(&streamlist,tcp_list_sync_compare,&confirm) ) {
		s->streamstate = STATUS_OK;
		s->lastdirection = DST_TO_SRC;
		s->lastacknumber = s->lastseqnumber + 1;
		s->lastseqnumber = seqnumber;
		s->time_lastpkt_dst = curtime;
		s->lastpayloadlen = 1; // the first pkt after sync have ack-number raised of 1...
		s->n_pkt++;
		printf("tcp_confirmconn: Acknowledgement from %s:%d to %s:%d (SYN/ACK)\n", ipv4addr_tostr(sa, &srcip), srcport, ipv4addr_tostr(da, &dstip), dstport);
	}
	
}

void tcp_resetconn(u_int32_t srcip, u_int32_t dstip, u_int16_t srcport, u_int16_t dstport, u_int32_t acknumber) {
	struct stream *s;
	char sa[64], da[64];
	struct tcp_list_sync_data reset;
	
	reset.ipsrc = srcip;
	reset.ipdst = dstip;
	reset.portsrc = srcport;
	reset.portdst = dstport;
	reset.acknumber = acknumber;
	
	if ( s = (struct stream *) list_find_del(&streamlist,tcp_list_sync_compare,&reset) ) {
		free(s);
		printf("tcp_resetconn: Reset from %s:%d to %s:%d (RST/ACK)\n", ipv4addr_tostr(sa, &srcip), srcport, ipv4addr_tostr(da, &dstip), dstport);
	}
	
}

struct tcp_list_oksync_data {
	u_int32_t ipsrc;
	u_int32_t ipdst;
	u_int16_t portsrc;
	u_int16_t portdst;
	u_int32_t seqnumber;
	u_int32_t acknumber;
	
	// Fields written by tcp_list_oksync_compare
	enum direction dir;
	enum syncstate syn;
};
int tcp_list_oksync_compare(void *data, void *cmpdata) {
	struct tcp_list_oksync_data *c = (struct tcp_list_oksync_data *)cmpdata;
	struct stream *s = (struct stream *)data;
	
	u_int32_t tmp;
	
	if ( !(s->type == TCP && s->streamstate == STATUS_OK) )
		return 0;
	
	if (	s->ipsrc == c->ipsrc &&
		s->ipdst == c->ipdst &&
		s->portsrc == c->portsrc &&
		s->portdst == c->portdst )
		c->dir = SRC_TO_DST;
	else
		if  (	s->ipdst == c->ipsrc &&
			s->ipsrc == c->ipdst &&
			s->portdst == c->portsrc &&
			s->portsrc == c->portdst )
			c->dir = DST_TO_SRC;
		else
			return 0;
	
	/* SYNCRONIZATION CONTROL -> check whether the packet has the right seqnumber and acknumber
	 * Many file transfer apps will not admit NOTSYNC packets, because file shouldn't have gaps... 
	 * Normal sniffers and IDS doesn't recognize this difference... (eg. snort) */
	
	if ( (c->dir != s->lastdirection && c->seqnumber == s->lastacknumber && c->acknumber == (s->lastseqnumber + s->lastpayloadlen)) ||
	       (c->dir == s->lastdirection && c->seqnumber == (s->lastseqnumber + s->lastpayloadlen) && c->acknumber == s->lastacknumber) ) 
		c->syn = SYNC;
	else
		if ( (c->dir != s->lastdirection && c->seqnumber == s->lastacknumber && c->acknumber == (s->lastseqnumber + s->lastpayloadlen)) ||
		       (c->dir == s->lastdirection && c->seqnumber > (s->lastseqnumber + s->lastpayloadlen) && c->acknumber == s->lastacknumber) ) 
			c->syn = NOTSYNC; //FIXME: check condition...
		else
			return 0;
	
	return 1;
}

void tcp_delconnection (struct stream *s) {
	if (s->filterdata) free(s->filterdata); // Free filter data, if not already freed...
	free(s);
}


int stream_n_connections() {
	return streamlist.list_len;
}


void stream_managepkt(struct IpHdr *ip, unsigned long long int n_pkt, double curtime) {
	char sa[64], da[64];
	int iphdrlen = ip->ihl << 2;
	
	
	extprintf("%lld)totlen:%d -ip %s -> %s -",
			n_pkt,
			ntohs(ip->tot_len),
			ipv4addr_tostr(sa, &ip->saddr),
			ipv4addr_tostr(da, &ip->daddr));
	
	if (ip->protocol == 6) {
		//TCP stuff
		struct TcpHdr *tcp = (void*)ip + iphdrlen;
		int tcphdrlen = ntohs(ip->tot_len)-iphdrlen;
		int dataoff = tcp->th_off << 2;
		
		
		void *payload = (void*)tcp + dataoff;
		int payloadlen = tcphdrlen-dataoff;
		
		u_int16_t sport,dport;
		u_int32_t seq,ack;
		
		sport = ntohs(tcp->th_sport);
		dport = ntohs(tcp->th_dport);
		seq = ntohl(tcp->th_seq);
		ack = ntohl(tcp->th_ack);
		
		char flags[16];
		
		extprintf("TCP-");
		extprintf("FLAGS:%s-",tcp_strflags(flags, tcp->th_flags));
		if (tcp->th_flags == TCP_SYN) {
			extprintf("TCP_CONNECT_REQ\n");
			tcp_addconnection(ip->saddr,ip->daddr,sport,dport,seq,curtime);
			return;
		}
		else 
		if (tcp->th_flags == TCP_SYNACK) {
			extprintf("TCP_CONNECT_ACK\n");
			tcp_confirmconn(ip->saddr,ip->daddr,sport,dport,seq,ack,curtime);
			return;
		}
		else
		if (tcp->th_flags == TCP_RSTACK) {
			extprintf("TCP_CONNECT_RST-No port\n");
			tcp_resetconn(ip->saddr,ip->daddr,sport,dport,ack);
			return;
		}
		else
		if ((tcp->th_flags & TCP_ACK) && !(tcp->th_flags & TCP_SYN) &&!(tcp->th_flags & TCP_RST)) {
			// a normal pkt has ACK set, if payloadlen > 0 has also PSH set
			struct stream *s;
			struct tcp_list_oksync_data cmpdata;
			u_int32_t tmp;
			int i;
			
			cmpdata.ipsrc = ip->saddr;
			cmpdata.ipdst = ip->daddr;
			cmpdata.portsrc = sport;
			cmpdata.portdst = dport;
			cmpdata.seqnumber = seq;
			cmpdata.acknumber = ack;

			if (tcp->th_flags & TCP_FIN) {
				extprintf("FINISH_PKT\n");
				s = (struct stream *) list_find_del(&streamlist,tcp_list_oksync_compare,&cmpdata);
				if (s) tcp_delconnection(s);
				return;
			}


			s = (struct stream *) list_find(&streamlist,tcp_list_oksync_compare,&cmpdata);

			if (!s)
				return; // No tcp connections associated with the packet...


			// Update tcp infos...
			//FIXME: function with NOTSYNC transfers???
			if (s->lastdirection == cmpdata.dir) {
				s->lastseqnumber = s->lastseqnumber + s->lastpayloadlen;
			}
			else {
				tmp = s->lastseqnumber;
				s->lastseqnumber = s->lastacknumber;
				s->lastacknumber = tmp + s->lastpayloadlen;
			}

			s->lastpayloadlen = payloadlen;
			s->lastdirection = cmpdata.dir;
			switch (cmpdata.dir) {
				case SRC_TO_DST: {
					s->time_lastpkt_src = curtime;
					break;
				}
				case DST_TO_SRC: {
					s->time_lastpkt_dst = curtime;
					break;
				}
			}
			s->n_pkt++;

			// TCP stuff finish here...
			// Now, filter handling...
			if (s->filterstate == NOTINTERESTING) {
				extprintf("NO_FILTER\n");
				return; // can we put this before tcp checks ??
			}
			if (s->filterstate == INDIFFERENT) {
				for (i=0; i<N_FILTERS; i++)
					if ( (s->filt.filterlist[i])->isInteresting(s->ipsrc, s->ipdst, s->portsrc, s->portdst, payload, payloadlen) ) {
						s->filt.activefilter = s->filt.filterlist[i];
						s->filterstate = INTERESTING;
						extprintf("ASSOCIATED_FILTER:%s\n",(s->filt.filterlist[i])->name);
						break;
					}
				if (s->n_pkt > 10)
					s->filterstate = NOTINTERESTING;
				// avoid searching infinitely for a filter...
			}
			if (s->filterstate == INTERESTING) {
				extprintf("FILTER:%s\n",(s->filt.activefilter)->name);
				(s->filt.activefilter)->pktin(payload, payloadlen, cmpdata.dir, cmpdata.syn, &(s->filterdata) );
			}

			// end filter handling.

		}
	}
	else
		extprintf("NO_TCP_PKT\n");
}



