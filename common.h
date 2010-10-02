/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: common.h,v 1.1 2004/04/13 09:17:08 flagz Exp $
 */


#ifndef _COMMON_H
#define _COMMON_H

/* Convert MAC address to string */
char *mac2string(struct ether_addr *eth, char *str) {
	sprintf(str,"%02X:%02X:%02X:%02X:%02X:%02X",
	    eth->ether_addr_octet[0],
	    eth->ether_addr_octet[1],
	    eth->ether_addr_octet[2],
	    eth->ether_addr_octet[3],
	    eth->ether_addr_octet[4],
	    eth->ether_addr_octet[5]);
	return str;
}

/* Convert IP address to string */
char *ipv4addr_tostr(char *s, void *addr)
{
	unsigned char *x = addr;

	sprintf(s, "%u.%u.%u.%u", x[0], x[1], x[2], x[3]);
	return s;
}


// TCP SPECIFIC FUNCTIONS
/* Convert TCP flags to string */
char *tcp_strflags(char *s, unsigned int flags)
{
	char *ftab = "FSRPAYXY", *p = s;
	int bit = 0;

	while(bit < 8) {
		if (flags & (1 << bit))
			*p++ = ftab[bit];
		bit++;
	}
	*p = '\0';
	return s;
}

#endif /* _COMMON_H */
