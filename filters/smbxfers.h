/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: smbxfers.h,v 1.1.1.1 2004/02/06 11:57:52 flagz Exp $
 */ 

 
#ifndef _SMB_XFERS_H
#define _SMB_XFERS_H	1

#include <stdlib.h>
#include "smbstructs.h"
#include "streamstructs.h"
#include "streamassembler.h" // for enum direction and syncstate...

#define FILENAME_MAX_LEN 256
#define NETBIOS_NAME_MAXLEN	17
#define SMB_MAX_XFERS 1000

struct smbxfer {
	char netbios_srcname[NETBIOS_NAME_MAXLEN];
	char netbios_dstname[NETBIOS_NAME_MAXLEN];
	
	u_int16_t fid;
	char fname[FILENAME_MAX_LEN];
	u_int32_t ftotalsize;
	u_int32_t fxferredsize;
	enum {WAIT_SRV_CONF,XFER_IN_PROGRESS,XFER_FINISHED} status;
	enum {NB_NEED_CONTINUATION_DATA,NB_NONEED_CONT_DATA} progress_xfer_continuation;
	int xfer_cont_remain_bytes;
	int fp;
};

// number of xfers active...
extern int n_xfers;


#endif /* _SMB_XFERS_H */
