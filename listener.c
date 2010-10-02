/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: listener.c,v 1.3 2004/04/13 09:15:02 flagz Exp $
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>

#include "listener.h"
#include "list-queue.h"

#ifdef EXTENDED_INFOS
#define extprintf(...)	printf(__VA_ARGS__)
#else
#define extprintf(...)
#endif


DECLARE_LIST(pktqueue);

const struct sched_param sp;

struct listener listeners[N_LISTENERS];


void listener_init() {
	strcpy(listeners[0].name,"sniff");
	listeners[0].type = CONCURRENT;
	listeners[0].main = sniff_main;
	listeners[0].enqueue = NULL;

	strcpy(listeners[1].name,"arphijack");
	listeners[1].type = CONCURRENT;
	listeners[1].main = arphijack_main;
	listeners[1].enqueue = NULL;
	
	// IF A LISTENER HAS AN ENQUEUE FUNCTION, IT MUST BE TYPE=WAIT
	
	// other listener initialization here...
}

void listener_start(struct listenparams *p, int active_listener) {
	pthread_t idmain, idenqueue;
	int i;
	void (*func1)(struct listenparams *);
	void (*func2)(struct listenparams *);
	
	sp.sched_priority = -15;	
	
	list_init(&pktqueue);
	

	printf("listener_start: Creating %s thread...\n",listeners[active_listener].name);

	func1 = listeners[active_listener].main;
	func2 = listeners[active_listener].enqueue;
	
	if (pthread_create(&idmain,NULL,func1,p) != 0) {
		printf("listener_start: Cannot create main thread...\n");
		exit(2);
	}
	
	// pthread_setschedparam(idmain, SCHED_RR, &sp); // useful??
	
	if (listeners[active_listener].type == WAIT) {
		pthread_join(idmain, NULL);
		if (func2 != NULL)
			if (pthread_create(&idenqueue,NULL,func2,p) != 0) {
				printf("listener_start: Cannot create enqueue thread...\n");
				exit(2);
			}
	}
	
}

// Return the first packet on the queue..
struct packet *listener_receivepkt() {
	return (struct packet *)queue_out(&pktqueue);
}

// Free memory used by the packet...
void listener_freepkt(struct packet *pk) {
	free(pk);
}

int listener_packetsqueued() {
	return pktqueue.list_len;
}

// Append packet in the queue
void pktqueue_append(struct packet *pk){
	queue_in(&pktqueue,(void *)pk);
}


