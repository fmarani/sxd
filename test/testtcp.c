#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>

#include "streamassembler.h"
#include "streamstructs.h"

/* Dimensione massima del pacchetto */
#ifndef IPMAX
	#define IPMAX	1500
#endif
#ifndef HDRMAX
	#define HDRMAX	14
#endif
#define PKTMAX	(IPMAX+HDRMAX)

struct sniffparams {
	int online_mode;
	char *ifname;
	char *targetmachine;
};

/* Cerca di indovinare l'offset del pacchetto IP. Ritorna
 * -1 se fallisce */
int guess_linkhdr_len(pcap_t *pfp) {
	switch (pcap_datalink(pfp)) {
		case DLT_EN10MB: {
			return 14;
			break;
		}
		default: {
			printf("guess_linkhdr_len: Cannot recognize link-header length, assuming ethernet...\n");
			return 14;
		}
	}
}

void sniff(struct sniffparams *p) {
	pcap_t *pcapfp;
	struct bpf_program bpfp;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned long long int n_pkt = 0;
	int linkhdr_len;
	/* FIXME: Aggiungere controllo se ip sorgente o ip destinazione è la TARGETMACHINE */
        char filter[] = "tcp";
	
	struct pcap_pkthdr hdr;
	unsigned char *pkt;
	struct IpHdr *ip;
	struct pcap_stat ps;
	double x,curtime;
	
	/* Apre le libpcap, utilizzando il nome dell'interfaccia
	 * passato alla funzione. */
	if (p->online_mode)
	   pcapfp = pcap_open_live(p->ifname, PKTMAX, 1, 0, errbuf);
	else
	    pcapfp = pcap_open_offline(p->ifname, errbuf);

	if (pcapfp == NULL) {
		fprintf(stderr, "Error opening libpcap: %s\n",
				errbuf);
		exit(1);
	}

	/* Compila e setta il programma BPF */
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
	
	linkhdr_len = guess_linkhdr_len(pcapfp);
	
	
	filter_init();
	
	
	
	/* Inizia il loop infinito che legge i pacchetti uno dopo l'altro */
	while(1) {
		/* La funzione pcap_next() restituisce il prossimo
		 * pacchetto in coda */
		pkt = (unsigned char*) pcap_next(pcapfp, &hdr);
		if (pkt == NULL)
			continue;
		
		n_pkt++;	
		
		// processiamo solo pacchetti interi...
		if (hdr.caplen != hdr.len) {
			printf("Skipping half-captured packet...\n");
			continue;
		}
		
		if (pcap_stats(pcapfp, &ps) == 0)
			printf("%lld)STATS-->PKT RECEIVED:%d, PKT DROPPED: %d\n",n_pkt,ps.ps_recv,ps.ps_drop);
		else
			printf("unable to get stats...\n");
		
		ip = (struct IpHdr *) (pkt+linkhdr_len);
		/* Visualizza il pacchetto */
		x = (double) hdr.ts.tv_usec;
		while (x > 1) {
			x /= 10;
		}
		curtime = (double)(x+hdr.ts.tv_sec);
		
		stream_managepkt(ip,n_pkt,curtime);
	}
	/* non raggiunto */
	pcap_close(pcapfp);
}
 

int main(int argc, char **argv) {
        struct sniffparams p;
	
	if (argc < 2) {
		fprintf(stderr, "Usage: sxd <(device|file)> <name> [targetmachine]\n");
		exit(1);
	}
	
	if (nice(-10) == -1) {
		perror("nice");
	}
	
	p.online_mode = (strcmp(argv[1],"device") == 0)? 1 : 0;
	
	if (p.online_mode)
		printf("Sniffing directly on device %s...\n",argv[2]);
	else
		printf("Reading sniffed data from file %s...\n",argv[2]);
	
	p.ifname = argv[2];
	p.targetmachine = argv[3];
	
	sniff(&p);
	
	// qua non ci arriviamo mai...
	return 0;
}
