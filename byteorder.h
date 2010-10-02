/* Original code from the Linux C library */
/* This code is under the original GNU C library license (GPL) */

#ifndef _BYTESEX_H
#define _BYTESEX_H

#if 	defined(__i386__) \
	|| defined(__alpha__) \
	|| (defined(__mips__) && (defined(MIPSEL) || defined (__MIPSEL__)))
#define BYTE_ORDER_LITTLE_ENDIAN
#elif 	defined(__mc68000__) \
	|| defined (__sparc__) \
	|| defined (__sparc) \
	|| defined (__PPC__) \
	|| (defined(__mips__) && (defined(MIPSEB) || defined (__MIPSEB__)))
#define BYTE_ORDER_BIG_ENDIAN
#else
# error can not find the byte order for this architecture, fix bytesex.h
#endif

#endif /* _BYTESEX_H */
