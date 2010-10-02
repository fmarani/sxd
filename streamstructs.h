/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: streamstructs.h,v 1.1.1.1 2004/02/06 11:57:52 flagz Exp $
 */ 

#ifndef _STREAMSTRUCTS_H
#define _STREAMSTRUCTS_H
 
#include "byteorder.h" 
#include <stdlib.h> // needed for compilation of structs...

/* IP header struct */
struct IpHdr {
#if defined(BYTE_ORDER_LITTLE_ENDIAN)
	u_int8_t	ihl:4,
			version:4;
#elif defined (BYTE_ORDER_BIG_ENDIAN)
        u_int8_t	version:4,
			ihl:4;
#else
#error  "Please, edit Makefile and add -DBYTE_ORDER_(BIG|LITTLE)_ENDIAN"
#endif
	u_int8_t	tos;
	u_int16_t	tot_len;
	u_int16_t	id;
	u_int16_t	frag_off;
	u_int8_t	ttl;
	u_int8_t	protocol;
	u_int16_t	check;
	u_int32_t	saddr;
	u_int32_t	daddr;
};

/* TCP header struct */
struct TcpHdr {
	u_int16_t	th_sport;               /* source port */
	u_int16_t	th_dport;               /* destination port */
	u_int32_t	th_seq;                 /* sequence number */
	u_int32_t	th_ack;                 /* acknowledgement number */
#if defined (BYTE_ORDER_LITTLE_ENDIAN)
	u_int8_t	th_x2:4,                /* (unused) */
			th_off:4;               /* data offset */
#elif defined (BYTE_ORDER_BIG_ENDIAN)
	u_int8_t	th_off:4,               /* data offset */
			th_x2:4;                /* (unused) */
#else
#error  "Please, edit Makefile and add -DBYTE_ORDER_(BIG|LITTLE)_ENDIAN"
#endif
	u_int8_t    th_flags;
	u_int16_t   th_win;                 /* window */
	u_int16_t   th_sum;                 /* checksum */
	u_int16_t   th_urp;                 /* urgent pointer */
};

/* add UDP structs ... */


#endif /* _STREAMSTRUCTS_H */

