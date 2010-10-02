/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: smbstructs.h,v 1.1.1.1 2004/02/06 11:57:52 flagz Exp $
 */ 

#ifndef _SMBSTRUCTS_H
#define _SMBSTRUCTS_H
 
#include <stdlib.h> // needed for compilation of structs...


// NetBIOS / SMB structures
#define NetBIOSHdrLen	4
struct NetBIOSHdr {
       u_int8_t nbtype;
       u_int8_t flags;
       u_int16_t len;
} __attribute__((packed));

#define SMBHdrLen	32
struct SMBHdr {
	u_int8_t head;
	char magicnum[3];
	u_int8_t com;
	u_int8_t errclass;
	u_int8_t :8;
	u_int16_t errcode;
	u_int8_t flags;
	u_int16_t flags2; //FIXME: Used also as flags
	u_int32_t :32;
	u_int32_t :32;
	u_int32_t :32;
	u_int16_t tid;
	u_int16_t pid;
	u_int16_t uid;
	u_int16_t mid;
} __attribute__((packed)); //PACKED because compiler wrong-align...


// smb structures used in xfers...
#define SMBOpenAndXReqLen	33
struct SMBOpenAndXReq {
	u_int8_t wordcount;
	u_int8_t andxcommand;
	u_int8_t :8;
	u_int16_t andxoffset;
	u_int16_t flags;
	u_int16_t desaccess;
	u_int16_t searchattr;
	u_int16_t fileattr;
	u_int32_t ctime;
	u_int16_t openfunc;
	u_int32_t allocsize;
	u_int64_t :64;
	u_int16_t bytecount;
	/* file name follows */
} __attribute__((packed));

#define SMBOpenAndXResLen	33
struct SMBOpenAndXRes {
	u_int8_t wordcount;
	u_int8_t andxcommand;
	u_int8_t :8;
	u_int16_t andxoffset;
	u_int16_t fid;
	u_int16_t fileattr;
	u_int32_t mtime;
	u_int32_t filesize;
	u_int16_t grantedaccess;
	u_int16_t filetype;
	u_int16_t ipcstate;
	u_int16_t action;
	u_int32_t server_fid;
	u_int16_t :16;
	u_int16_t bytecount;
} __attribute__((packed));


// Instead of OpenAndX, win2000 and > use CreateAndX 
#define SMBCreateAndXReqLen	52
struct SMBCreateAndXReq {
	u_int8_t wordcount;
	u_int8_t andxcommand;
	u_int8_t :8;
	u_int16_t andxoffset;
	u_int8_t :8;
	u_int16_t filenamelen;
	u_int32_t createflags;
	u_int32_t rootfid;
	u_int32_t accessmask;
	u_int64_t allocationsize;
	u_int32_t fileattrib;
	u_int32_t shareaccess;
	u_int32_t disposition;
	u_int32_t createopts;
	u_int32_t impersonalization;
	u_int8_t securityflags;
	u_int16_t bytecount;
	u_int8_t :8;
	/* file name follows */
} __attribute__((packed));

#define SMBCreateAndXResLen	71
struct SMBCreateAndXRes {
	u_int8_t wordcount;
	u_int8_t andxcommand;
	u_int8_t :8;
	u_int16_t andxoffset;
	u_int8_t oplocklevel;
	u_int16_t fid;
	u_int32_t createaction;
	u_int64_t created;
	u_int64_t lastaccess;
	u_int64_t lastwrite;
	u_int64_t change;
	u_int32_t fileattr;
	u_int64_t allocsize;
	u_int64_t eof;
	u_int16_t filetype;
	u_int16_t ipcstate;
	u_int8_t is_a_directory;
	u_int16_t bytecount;
} __attribute__((packed));




#define SMBReadAndXReqLen	23
struct SMBReadAndXReq {
	u_int8_t wordcount;
	u_int8_t andxcommand;
	u_int8_t :8;
	u_int16_t andxoffset;
	u_int16_t fid;
	u_int32_t offset;
	u_int16_t maxbytecount;
	u_int16_t minbytecount;
	u_int32_t :32;
	u_int16_t remaining;
	u_int16_t bytecount;
} __attribute__((packed));

#define SMBReadAndXResLen	27
struct SMBReadAndXRes {
	u_int8_t wordcount;
	u_int8_t andxcommand;
	u_int8_t :8;
	u_int16_t andxoffset;
	u_int16_t remaining;
	u_int16_t datacompactionmode;
	u_int16_t :16;
	u_int16_t datalength;
	u_int16_t dataoffset;
	u_int32_t :32;
	u_int32_t :32;
	u_int16_t :16;
	u_int16_t bytecount;
} __attribute__((packed));

#define SMBCloseReqLen	9
struct SMBCloseReq {
	u_int8_t wordcount;
	u_int16_t fid;
	u_int32_t lastwrite;
	u_int16_t bytecount;
} __attribute__((packed));
 

#endif  /* _SMBSTRUCTS_H */
