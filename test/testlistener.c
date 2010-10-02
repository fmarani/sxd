#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include "listener.h"

void stop() {
	printf("CTRL+C --> Stop sniffing...\n");
	exit(0);
}

int main(int argc, char **argv) {
	struct listenparams p;
	struct packet *pk;
	char *c;
	u_int32_t *u;
	int active_listener = -1;
	int i;

	listener_init();

	if (argc < 5) {
		fprintf(stderr, "Usage: testlistener <listenername> <online_mode> <ifname> <targetmachine>\n");
		fprintf(stderr, "\nAvailable listeners:\n");
		for (i=0; i<N_LISTENERS; i++) {
			fprintf(stderr, listeners[i].name);
			fprintf(stderr, "\n");
		}
		exit(1);
	}
	for (i=0; i<N_LISTENERS; i++)
		if (strcmp(argv[1],listeners[i].name) == 0) {
			active_listener = i;
			break;
		}
	if (active_listener == -1) {
		fprintf(stderr, "Listener not found\n");
		exit(1);
	}

	signal(SIGINT,stop);

	p.online_mode = atoi(argv[2]);
	strcpy(p.ifname,argv[3]);  // HORRIBLE OVERFLOW :))
	strcpy(p.targetmachine,argv[4]); // also here

	printf("TESTLISTENER [listener=%s] [online_mode=%d] [ifname=%s] [targetip=%s]\n",listeners[active_listener].name,p.online_mode,p.ifname,p.targetmachine);	

	listener_start(&p,active_listener);

	while (1) {
		printf("Waiting packets...\n");
		pk = listener_receivepkt();
		// for (i=0;i<2000000;i++); //introduce Overhead...
		printf("PKT: %lld) curtime: %5.4f ---- pkt_in_queue: %d --",pk->n_pkt,pk->curtime,listener_packetsqueued());
		c = (char *) pk->pkt + 14;
		u = (u_int32_t *) (c+20+4) ;
		printf(" Sequencenum: %d\n",ntohs(*u));
		listener_freepkt(pk);
	}
	// not reached
	return 0;
}
