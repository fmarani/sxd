/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: listener.h,v 1.3 2004/04/13 09:15:02 flagz Exp $
 */ 


#ifndef _LISTENER_H
#define _LISTENER_H	1

// max dimension for a pkt IP (for ethernet it's ok..)
#define IPMAX	1500

#define HDRMAX	14
#define PKTMAX	IPMAX+HDRMAX	// these are used inside listeners... out is only IPMAX

// NOTE THAT THIS IS AN IP PACKET (NO LINK HEADERS!!!)
struct packet {
	unsigned long long int n_pkt;
	double curtime;
	char pkt[IPMAX];
};

struct listenparams {
	int online_mode;
	char ifname[100];
	char targetmachine[100];
};

struct listener {
	char name[20];
	enum { CONCURRENT, WAIT } type;
	void (*main)(struct listenparams *);
	void (*enqueue)(struct listenparams *);
};

/* listener prototipes  */

void sniff_main(struct listenparams *);
void arphijack_main(struct listenparams *);


/* end listener prototipes  */

#define N_LISTENERS	2

extern struct listener listeners[N_LISTENERS];


struct packet *listener_receivepkt();   // called by stream assembler...
void listener_freepkt(struct packet *pk);

int listener_packetsqueued();

void listener_start(struct listenparams *p, int active_listener);  // called by sxd.c - main
void listener_init();

void pktqueue_append(struct packet *pk);  // called by listeners


#endif /* _LISTENER_H */
