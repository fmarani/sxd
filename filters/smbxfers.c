/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: smbxfers.c,v 1.1.1.1 2004/02/06 11:57:52 flagz Exp $
 */ 



#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "smbxfers.h"

#ifdef EXTENDED_INFOS
#define extprintf(...)	printf(__VA_ARGS__)
#else
#define extprintf(...)
#endif


int n_xfers = 0;

void addsmbxfer(struct smbxfer *xfer, char *fname, int flen) {
	#if SMB_MAX_XFERS != 0
	if (n_xfers >= SMB_MAX_XFERS)
		return;
	#endif
	
	xfer->fid = 0;
	strncpy(xfer->fname,fname,(flen > FILENAME_MAX_LEN-1 ? FILENAME_MAX_LEN-1 : flen));
	xfer->fname[(flen > FILENAME_MAX_LEN-1 ? FILENAME_MAX_LEN-1 : flen)] = '\0';
	xfer->ftotalsize = 0;
	xfer->fxferredsize = 0;
	xfer->status = WAIT_SRV_CONF;
	xfer->fp = -1;
	printf("File (%s) -> Transfer ready to start... flen:%d\n",xfer->fname,flen);
	
	n_xfers++;
}

void openfileforsmbxfer(struct smbxfer *p) {
	printf("Sniffing automatic...\n");
	if (strcmp(p->fname,"\\spoolss") == 0 ||
	    strcmp(p->fname,"\\srvsvc") == 0 ||
	    strcmp(p->fname,"\\wkssvc") == 0 ||
	    strcmp(p->fname,"\\winreg") == 0 ||
	    strncmp(p->fname,"\\PIPE",5) == 0) {
		printf("openfile: not useful data\n");
		return;
	}
	p->fp = open(p->fname,O_WRONLY | O_CREAT,0644);
	if (p->fp < 0)
		perror("openfile: Failed creation for writing...\n");
	else
		printf("openfile: Creating successful...\n");
}

void confirmsmbxfer(struct smbxfer *xfer, u_int16_t fid, u_int32_t fsize) {
	if (xfer == NULL) return;
	if (xfer->status == WAIT_SRV_CONF) {
		xfer->fid = fid;
		xfer->ftotalsize = fsize;
		xfer->status = XFER_IN_PROGRESS;
		xfer->progress_xfer_continuation = NB_NONEED_CONT_DATA;
		printf("File (%s) <- Transfer confirmed,FID:%u,SIZE:%lu bytes...\n",xfer->fname,fid,fsize);
		openfileforsmbxfer(xfer);
	}
}

void smbxferrequest(struct smbxfer *xfer, u_int16_t fid, u_int32_t offset)  {
	if (xfer == NULL) return;
	if (xfer->fid == fid &&
	    xfer->status == XFER_IN_PROGRESS) {
		if (xfer->fxferredsize == offset) { //starts from where the last time exits...FIXME:this condition have to always occur, otherwise the file will corrupt...
			printf("File (%s) -> DATA REQUEST, Offset: %ld\n",xfer->fname,offset);
		}
		else {
			printf("File (%s) -> ERROR, MISMATCHED DATA REQ OFFSET,catched:%lu,expected:%lu\n",xfer->fname,offset,xfer->fxferredsize);
		}
	}
}


void smbxferresponse(struct smbxfer *xfer, u_int16_t bytecount, void *buffer)  {
	if (xfer == NULL) return;
	if (xfer->status == XFER_IN_PROGRESS) {
		printf("File (%s) <- DATA RECEIVED, Bytes received: %d\n",xfer->fname,bytecount);
		if (xfer->fp != -1 && bytecount > 0) {
			int wr_c;
			if ( (wr_c = write(xfer->fp,buffer,bytecount)) < 0) // Write the file-slice to the disk...
				perror("Error while writing");
			else
				printf("%d bytes written on disk...\n",wr_c);
		}
		xfer->fxferredsize += bytecount;
	}
}

void closesmbxfer(struct smbxfer *xfer, u_int16_t fid) {
	if (xfer == NULL) return;
	if (xfer->fid == fid &&
	    xfer->status == XFER_IN_PROGRESS) {
		if (xfer->fp != -1)
			close(xfer->fp); // Close file, finish capture...
		xfer->status = XFER_FINISHED;
		printf("File (%s) -- Transfer finished\n",xfer->fname);
	}
	n_xfers--;
}

void smb_nbsetcontinuation(struct smbxfer *xfer, int nbytes) {
	if (xfer == NULL) return;
	if (xfer->status == XFER_IN_PROGRESS) {
		xfer->progress_xfer_continuation = NB_NEED_CONTINUATION_DATA;
		xfer->xfer_cont_remain_bytes = nbytes;
		printf("File (%s) -- Setting continuation-mode...\n",xfer->fname);
	}
}

void smb_nbunsetcontinuation(struct smbxfer *xfer) {
	if (xfer == NULL) return;
	if (xfer->status == XFER_IN_PROGRESS) {
		xfer->progress_xfer_continuation = NB_NONEED_CONT_DATA;
		printf("File (%s) -- Unsetting continuation-mode...\n",xfer->fname);
	}
}

int smb_nbneedcontinuation(struct smbxfer *xfer) {
	if (xfer == NULL) return 0;
	if (xfer->status == XFER_IN_PROGRESS) {
		if (xfer->xfer_cont_remain_bytes == 0)
			xfer->progress_xfer_continuation = NB_NONEED_CONT_DATA;
		return xfer->progress_xfer_continuation == NB_NEED_CONTINUATION_DATA;
	}
	return 0;
}

void smb_nbfeedcontinuationdata(struct smbxfer *xfer, void* buffer, int bufferlen) { //USE ONLY IN RESPONSE...
	if (xfer == NULL) return;
	if (xfer->status == XFER_IN_PROGRESS &&
	    xfer->progress_xfer_continuation == NB_NEED_CONTINUATION_DATA) {
		printf("File (%s) <- DATA RECEIVED (CONTINUATION PKT), Bytes received: %d\n",xfer->fname,bufferlen);
		if (xfer->fp != -1 && bufferlen > 0) {
			int wr_c;
			if ( (wr_c = write(xfer->fp,buffer,bufferlen)) < 0) // write file-slice to disk...
				perror("Error while writing: ");
			else
				printf("%d bytes written on disk...\n",wr_c);
		}
		xfer->fxferredsize += bufferlen;
		xfer->xfer_cont_remain_bytes -= bufferlen;
	}
}


void nb_parse_nmb_names(struct smbxfer *xfer, struct NetBIOSHdr *nb, int payloadlen) {
	// this func extract only the first label, ignoring the scope... (often .NETBIOS.COM..., useless)
	unsigned char *pointer, tmp, tmp2;
	int namelen, i;
	pointer = (u_int8_t *)nb + NetBIOSHdrLen;
	namelen = *pointer;
	if (namelen != 0x20)
		return; // we only consider netbios-coded names = (and <) 32 bytes, and ignore label-pointers..
	pointer++;
	for (i=0; i<namelen; i += 2) {
		tmp = pointer[i] - 'A';
		tmp2 = pointer[i+1] - 'A';
		xfer->netbios_dstname[i/2] = (tmp << 4) | tmp2;
		if (xfer->netbios_dstname[i/2] == ' ')
			break;
	}
	xfer->netbios_dstname[i/2] = '\0';
	
	// ignore scope
	while (*pointer != 0x00)
		pointer++;
	pointer++;
	
	// the same for destination name
	namelen = *pointer;
	if (namelen != 0x20)
		return; 
	pointer++;
	for (i=0; i<namelen; i += 2) {
		tmp = pointer[i] - 'A';
		tmp2 = pointer[i+1] - 'A';
		xfer->netbios_srcname[i/2] = (tmp << 4) | tmp2;
		if (xfer->netbios_srcname[i/2] == ' ')
			break;
	}
	xfer->netbios_srcname[i/2] = '\0';
}




void manage_smb(struct smbxfer *xfer, struct SMBHdr *smb, int smblen, enum direction *dir) {
	// normal smb packet, not netbios continuation pkt...
	//FIXME: add check: request must be SRC_TO_DST and response DST_TO_SRC..
	if (smb->com == 0x2d) {
		// Open AndX Request/Response
		printf("OpenAndX");
		if (!(smb->flags & 0x80)) {
			// Request...
			printf("Req-\n");
			struct SMBOpenAndXReq *req = (void*)smb + SMBHdrLen;
			addsmbxfer(xfer,(void*)req + SMBOpenAndXReqLen,req->bytecount); //FIXME: WHY ISN'T BYTECOUNT CONVERTED WITH NTOHS ?? 
		}
		else {
			// Response...
			printf("Res-\n");
			struct SMBOpenAndXRes *res = (void*)smb + SMBHdrLen;
			if (res->filetype == 0)
				confirmsmbxfer(xfer,ntohs(res->fid),res->filesize); // only file or directory (filetype = 0)
		}
	}
	else
	if (smb->com == 0xa2) {
		// NT Create AndX Request/Response
		printf("CreateAndX");
		if (!(smb->flags & 0x80)) {
			// Request...
			printf("Req-\n");
			struct SMBCreateAndXReq *req = (void*)smb + SMBHdrLen;
			//create filename... in createandx the name is written with a letter and a null char, alternatively
			char filename[1000];
			int i;
			for(i=0; i<(req->filenamelen) && i<2000; i+=2) {
				filename[i/2] = *((char *)req + SMBCreateAndXReqLen + i);
			}
			addsmbxfer(xfer,filename,(req->filenamelen)/2);
		}
		else {
			// Response...
			printf("Res-\n");
			struct SMBCreateAndXRes *res = (void*)smb + SMBHdrLen;
			if (smb->errclass == 0 && smb->errcode == 0 && res->filetype == 0 && res->is_a_directory == 0)
				confirmsmbxfer(xfer,ntohs(res->fid),res->eof); // only file or directory (filetype = 0)
		}
	}
	else
	if (smb->com == 0x2e) {
		// Read AndX Request/Response
		printf("ReadAndX");
		if (!(smb->flags & 0x80)) {
			// Request...
			printf("Req-\n");
			struct SMBReadAndXReq *req = (void*)smb + SMBHdrLen;
			smbxferrequest(xfer,ntohs(req->fid),req->offset); //FIXME: WHY ISN'T OFFSET CONVERTED WITH NTOHS ?? 
		}
		else {
			// Response...
			u_int16_t bytecount;
			int pkt_appendedbytes;
			int needcont = 0;

			printf("Res-\n");
			struct SMBReadAndXRes *res = (void*)smb + SMBHdrLen;

			// guarda se i byte spediti sono meno dei richiesti.. i rimanenti verranno spediti con un netbios continuation message
			pkt_appendedbytes = smblen-SMBHdrLen-SMBReadAndXResLen;
			if (res->bytecount > pkt_appendedbytes) {
				bytecount = pkt_appendedbytes;
				needcont = 1;
			}
			else
				bytecount = res->bytecount;

			smbxferresponse(xfer,bytecount,(void*)res + SMBReadAndXResLen); //FIXME: WHY ISN'T BYTECOUNT CONVERTED WITH NTOHS ?? 
			if (needcont)
				smb_nbsetcontinuation(xfer,res->bytecount - pkt_appendedbytes);
		}
	}
	else
	if (smb->com == 0x04) {
		// Close Request/Response
		printf("Close-\n");
		if (!(smb->flags & 0x80)) {
			// Request...
			struct SMBCloseReq *req = (void*)smb + SMBHdrLen;
			closesmbxfer(xfer,ntohs(req->fid));
		}
		// No Handler for Response, useless...
	}
	else
		printf("NOT_SUPPORTED_CMD\n");
}

int checkport(u_int32_t ipsrc, u_int32_t ipdst, u_int16_t portsrc, u_int16_t portdst, void *payload, int payloadlen) {
	if (portdst == 139 || portdst == 445)
		return 1;
	else
		return -1;
}
 
void manage_nb(void *payload, int payloadlen, enum direction dir, enum syncstate syn, void **filterdata) {
	struct NetBIOSHdr *nb = (struct NetBIOSHdr *)payload;
	struct smbxfer *xfer;
	
	if (*filterdata == NULL)
		if ( (*filterdata = malloc(sizeof(struct smbxfer))) == NULL ) {
			printf("manage_nb: Cannot allocate memory for smb transfers...\n");
			return;
		}
	
	xfer = (struct smbxfer *) *filterdata;
	
	if (payloadlen < NetBIOSHdrLen) {
		extprintf("LEN<NetBIOSHdrLen\n");
		return;
	}
	if (syn == NOTSYNC) {
		extprintf("SYNC_REQUIRED\n");
		return;
	}
	//NETBIOS stuff
	if (smb_nbneedcontinuation(xfer)) {
		extprintf("NB_CONTINUATION_DATA-\n");
		smb_nbfeedcontinuationdata(xfer,payload,payloadlen);
		return;
	}

	if (nb->nbtype == 0x81) {
		extprintf("NB_SESSION_REQUEST-\n");
		// estrapolate netbios host-names...
		nb_parse_nmb_names(xfer,nb,payloadlen);
		printf("NB -> %s is calling %s\n",xfer->netbios_srcname,xfer->netbios_dstname);
		return;
	}
	if (nb->nbtype == 0x82) {
		extprintf("NB_SESSION_POSITIVEREPLY-\n");

		return;
	}


	if (nb->nbtype == 0) {
		//SMB stuff
		struct SMBHdr *smb = payload + NetBIOSHdrLen;
		/* don't use nb->len because contain the whole dimension of the netbios-pkt
		which is bigger than a TCP pkt (usually)
		we only use the remaining data, and eventually set nb continuation mode... */
		int smblen = payloadlen - NetBIOSHdrLen;

		extprintf("NB_SESSION_MSG-");
		if (smb->head == 0xFF && smb->magicnum[0] == 'S' && smb->magicnum[1] == 'M' && smb->magicnum[2] == 'B')
			extprintf("VALID_SMB_PKT-");
		else {
			extprintf("INVALID_SMB_PKT-\n");
			return;
		}

		manage_smb(xfer,smb,smblen,&dir);
	}
	else
		extprintf("OTHER_NETBIOS_PKT\n");
}
