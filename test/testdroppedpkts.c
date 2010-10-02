

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>

#define EXTENDED_INFOS	1

#if EXTENDED_INFOS == 1
#define extprintf(...)	printf(__VA_ARGS__)
#else
#define extprintf(...)
#endif



struct sniffparams {
	int online_mode;
	char *ifname;
	char *targetmachine;
};


int guess_linkhdr_len(pcap_t *pfp) {
	switch (pcap_datalink(pfp)) {
		case DLT_EN10MB: {
			return 14;
			break;
		}
		default: {
			printf("guess_linkhdr_len: Cannot recognize link-header length\n");
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
        char filter[] = "tcp and (port 139 or port 445)";
	
	struct pcap_pkthdr hdr;
	unsigned char *pkt;
	struct IpHdr *ip;
	struct pcap_stat ps;
	double x,curtime;
	struct pkt_list *pk;
	
	/* Apre le libpcap, utilizzando il nome dell'interfaccia
	 * passato alla funzione. */
	if (p->online_mode) {
		printf("Sniffing directly on device %s...\n",p->ifname);
		pcapfp = pcap_open_live(p->ifname, 1514, 1, 0, errbuf);
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
	
	/* Inizia il loop infinito che legge i pacchetti uno dopo l'altro */
	while(1) {
		int i;
		/* La funzione pcap_next() restituisce il prossimo
		 * pacchetto in coda */
		printf("before pcap_next\n");
		pkt = (unsigned char*) pcap_next(pcapfp, &hdr);
		printf("after pcap_next\n");
		if (pkt == NULL)
			continue;
		
		n_pkt++;	
		
		// processiamo solo pacchetti interi...
		if (hdr.caplen != hdr.len) {
			printf("Skipping half-captured packet...\n");
			continue;
		}
		
		if (pcap_stats(pcapfp, &ps) == 0)
			extprintf("%lld)STATS-->PKT RECEIVED:%d, PKT DROPPED: %d\n",n_pkt,ps.ps_recv,ps.ps_drop);
		if (ps.ps_drop > 0)
			printf("PACKET DROPPED: %d\n",ps.ps_drop);
		
		ip = (unsigned char*) (pkt+linkhdr_len);
		/* Visualizza il pacchetto */
		x = (double) hdr.ts.tv_usec;
		while (x > 1) {
			x /= 10;
		}
		curtime = (double)(x+hdr.ts.tv_sec);
		for (i=0; i<1000; i++) ;
		
	}
	/* non raggiunto */
	pcap_close(pcapfp);
}


int main(int argc,char **argv) {
	struct sniffparams p;
	
	p.online_mode = 1;
	p.ifname = "eth0";
	p.targetmachine = "";
	
	sniff(&p);
}
