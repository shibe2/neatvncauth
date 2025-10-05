/*
 *  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* d3des.h -
 *	Graven Imagery, 1992.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge
 *	(GEnie : OUTER; CIS : [71755,204])
 */

#ifndef D3DES_H
#define D3DES_H

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define EN0	0	/* MODE == encrypt */
#define DE1	1	/* MODE == decrypt */

extern void des_set_key(uint32_t *, unsigned char *, int);
/*                      KnL[32]     hexkey[8]        MODE
 * Sets the schedule according to the hexadecimal
 * key contained in the 8 bytes of hexkey, according to the DES,
 * for encryption or decryption according to MODE.
 */

extern void des_crypt(const uint32_t *, unsigned char *, unsigned char *);
/*                    KnL[32]           from[8]          to[8]
 * Encrypts/Decrypts (according to the schedule)
 * one block of eight bytes at address 'from'
 * into the block at address 'to'.  They can be the same.
 */

#ifdef __cplusplus
}
#endif

#endif

/* d3des.h V5.09 rwo 9208.04 15:06 Graven Imagery
 ********************************************************************/
