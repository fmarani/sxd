/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: sxd.c,v 1.3 2004/04/13 09:15:02 flagz Exp $
 */



#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include "streamassembler.h"
#include "listener.h"

#define SXD_VERSION	"0.101"

void mainloop(struct listenparams *p, int active_listener) {
	struct packet *pk;


	listener_start(p, active_listener);

	while (1) {
		pk = listener_receivepkt();
		stream_managepkt(pk->pkt,pk->n_pkt,pk->curtime);
		listener_freepkt(pk);
	}
	//not reached
}

void stop() {
	printf("CTRL+C --> Stop sniffing...\n");
	exit(0);
}

void usage() {
	int i;
	fprintf(stderr, "SXD - SXD Xfer Dump v.");
	fprintf(stderr, SXD_VERSION);
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: sxd [-l listener] [-t target] [--dont-nice] <-i|-f> <ifname>\n");
	fprintf(stderr, "Usage: sxd -h\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-l -> specify a listener\n");
	fprintf(stderr, "-t -> specify a target machine (ip)\n");
	fprintf(stderr, "--dont-nice -> self-explaining:)\n");
	fprintf(stderr, "-i specify an interface where listen\n");
	fprintf(stderr, "-f or load data from file\n");
	fprintf(stderr, "\nAvailable listeners:\n");
	for (i=0; i<N_LISTENERS; i++) {
		fprintf(stderr, listeners[i].name);
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "\nAvailable filters:\n");
	for (i=0; i<N_FILTERS; i++) {
		fprintf(stderr, filters[i].name);
		fprintf(stderr, "\n");
	}
	exit(1);
}


int main(int argc, char **argv) {
        struct listenparams p = {-1, "", ""};
	int nicing = 1;
	int listener_to_use = -1;

	listener_init();
	stream_init();
	filter_init();


	while (1) {
		int opt,i;
		static struct option long_options[] = {
			{"interface", 1, 0, 'i'},
			{"file", 1, 0, 'f'},
			{"listener", 1, 0 , 'l'},
			{"target", 1, 0, 't'},
			{"dont-nice", 0, 0, 0},
			{"help", 1, 0, 'h'},
			{0, 0, 0, 0}
		};

		opt = getopt_long(argc, argv, "i:f:l:t:h", long_options, NULL);
		if (opt == -1)
			break;

		switch (opt) {
			case 0:
				nicing=0;
				break;
			case 'i':
				p.online_mode = 1;
				strncpy(p.ifname,optarg,100);
				break;
			case 'f':
				p.online_mode = 0;
				strncpy(p.ifname,optarg,100);
				break;
			case 't':
				strncpy(p.targetmachine,optarg,100);
				break;
			case 'l':
				for (i=0; i<N_LISTENERS; i++)
					if (strcmp(optarg,listeners[i].name) == 0) {
						listener_to_use = i;
						break;
					}
				break;
			case 'h':
				usage();
				break;
		}
	}

	if (nicing && (nice(-10) == -1)) {
		perror("nice");
	}

	signal(SIGINT,stop);

	if (p.online_mode == -1) {
		fprintf(stderr,"No interface selected - you have to specify -i or -f ...\n\n");
		usage();
	}

	mainloop(&p,listener_to_use);

	// not reached
	return 0;
}

