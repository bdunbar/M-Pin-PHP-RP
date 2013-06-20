/*
 * This file is part of CertiVox M-Pin Client and Server Libraries. 

The CertiVox M-Pin Client and Server Libraries provides developers with an extensive and efficient set of strong authentication and cryptographic functions. 

For further information about its features and functionalities please refer to http://www.certivox.com 

The CertiVox M-Pin Client and Server Libraries are free software: you can redistribute it and/or modify it under the terms of the BSD 3-Clause License http://opensource.org/licenses/BSD-3-Clause as stated below.

The CertiVox M-Pin Client and Server Libraries are distributed in the hope that they will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

Note that CertiVox Ltd. issues a patent grant for use of this software under specific terms and conditions, which you can find here: http://certivox.com/about-certivox/patents/ 

Copyright (c) 2013, CertiVox UK Ltd
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
•  Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
•  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
•  Neither the name of CertiVox Ltd nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/*** Basic Octet string maintainance routines  ***/

#include "octet.h"

/* Output an octet string (Debug Only) */

void OCTET_OUTPUT(octet *w)
{
    int i;
    unsigned char ch;
    for (i=0;i<w->len;i++)
    {
        ch=w->val[i];
        printf("%02x",ch);
    }
    printf("\n");
}        

void OCTET_OUTPUT_STRING(octet *w)
{
    int i;
    unsigned char ch;
    for (i=0;i<w->len;i++)
    {
        ch=w->val[i];
        printf("%c",ch);
    }
  /*  printf("\n"); */
}    

/* Convert C string to octet format - truncates if no room  */

void OCTET_JOIN_STRING(char *s,octet *y)
{
    int i,j;
    i=y->len;
    j=0;
    while (s[j]!=0 && i<y->max)
    {
        y->val[i]=s[j];
        y->len++;
        i++;  j++;
    }
}

/* compare 2 octet strings. 
 * If x==y return TRUE, else return FALSE */ 

int OCTET_COMPARE(octet *x,octet *y)
{
    int i;
    if (x->len>y->len) return 0;
    if (x->len<y->len) return 0;
    for (i=0;i<x->len;i++)
    {
        if (x->val[i]!=y->val[i]) return 0;
    }
    return 1;
}

/* Append binary string to octet - truncates if no room */

void OCTET_JOIN_BYTES(char *b,int len,octet *y)
{
    int i,j;
    i=y->len;
    for (j=0;j<len && i<y->max;j++) 
    {
        y->val[i]=b[j];
        y->len++;
        i++;
    }
}

/* Concatenates two octet strings */

void OCTET_JOIN_OCTET(octet *x,octet *y)
{ /* y=y || x */
    int i,j;
    if (x==NULL) return;

    for (i=0;i<x->len;i++)
    {
        j=y->len+i;
        if (j>=y->max)
        {
            y->len=y->max;
            return;
        }
        y->val[j]=x->val[i];
    }
    y->len+=x->len;
}

/* Append byte to octet rep times */

void OCTET_JOIN_BYTE(int ch,int rep,octet *y)
{
    int i,j;
    i=y->len;
    for (j=0;j<rep && i<y->max;j++) 
    {
        y->val[i]=ch;
        y->len++;
        i++;
    }
}

/* XOR common bytes of x with y */

void OCTET_XOR(octet *x,octet *y)
{ /* xor first x->len bytes of y */

    int i;
    for (i=0;i<x->len && i<y->len;i++)
    {
        y->val[i]^=x->val[i];
    }
}

/* clear an octet */

void OCTET_EMPTY(octet *w)
{
    w->len=0;
}

/* Kill an octet string - Zeroise it for security */

void OCTET_CLEAR(octet *w)
{
    int i;
    for (i=0;i<w->max;i++) w->val[i]=0;
    w->len=0;
}

/* OCTET_JOIN_LONG primitive */
/* appends long x of length len bytes to OCTET string */

void OCTET_JOIN_LONG(long x,int len,octet *y) 
{
    int i,j,n;
    n=y->len+len;
    if (n>y->max || len<=0) return;
    for (i=y->len;i<n;i++) y->val[i]=0;
    y->len=n;

    i=y->len; 
    while (x>0 && i>0)
    {
        i--;
        y->val[i]=x%256;
        x/=256;
    }
}

/* Pad an octet to a given length */

void OCTET_PAD(int n,octet *w)
{
	int i,d;
	if (w->len>=n || n>w->max) return;
	d=n-w->len;
	for (i=n-1;i>=d;i--)
		w->val[i]=w->val[i-d];
	for (i=d-1;i>=0;i--)
		w->val[i]=0;
	w->len=n;
}

/* Convert an octet string to base64 string */

void OCTET_TO_BASE64(octet *w,char *b)
{
	int i,j,k,rem,last;
	int c,ch[4];
	unsigned char ptr[3];
	rem=w->len%3; j=k=0; last=4;
	while (j<w->len)
	{
		for (i=0;i<3;i++)
		{
			if (j<w->len) ptr[i]=w->val[j++];
			else {ptr[i]=0; last--;}
		}
		ch[0]=(ptr[0]>>2)&0x3f;
		ch[1]=((ptr[0]<<4)|(ptr[1]>>4))&0x3f;
		ch[2]=((ptr[1]<<2)|(ptr[2]>>6))&0x3f;
		ch[3]=ptr[2]&0x3f;
		for (i=0;i<last;i++)
		{
			c=ch[i];
			if (c<26) c+=65;
            if (c>=26 && c<52) c+=71;
            if (c>=52 && c<62) c-=4;
            if (c==62) c='+';
            if (c==63) c='/';
			b[k++]=c;
		}
	}
	if (rem>0) for (i=rem;i<3;i++) b[k++]='=';
	b[k]='\0';  // dangerous!
}

void OCTET_FROM_BASE64(char *b,octet *w)
{
	int i,j,k,pads,len=strlen(b);
	int c,ch[4],ptr[3];
	int lead=1;
	j=k=0;
	while (j<len && k<w->max)
	{
		pads=0;
		for (i=0;i<4;i++)
		{
			c=80+b[j++];
			if (c<=112) continue; /* ignore white space */
            if (c>144 && c<171) c-=145;
            if (c>176 && c<203) c-=151;
            if (c>127 && c<138) c-=76;
            if (c==123) c=62;
            if (c==127) c=63;
            if (c==141) {pads++; continue;} /* ignore pads '=' */
			ch[i]=c;
		}
		ptr[0]=(ch[0]<<2)|(ch[1]>>4);
		ptr[1]=(ch[1]<<4)|(ch[2]>>2);
		ptr[2]=(ch[2]<<6)|ch[3];
		for (i=0;i<3-pads && k<w->max;i++)
		{ /* don't put in leading zeros */
			/* if (lead && ptr[i]==0) continue; */
			w->val[k++]=ptr[i];
			lead=0;
		}
		
	}
	w->len=k;
}

/* copy an octet string - truncates if no room */

void OCTET_COPY(octet *x,octet *y)
{
    int i;
    OCTET_CLEAR(y);
    y->len=x->len;
    if (y->len>y->max) y->len=y->max;

    for (i=0;i<y->len;i++)
        y->val[i]=x->val[i];
}

/* XOR m with all of x */

void OCTET_XOR_BYTE(int m,octet *x)
{
    int i;
    for (i=0;i<x->len;i++) x->val[i]^=m;
}

/* truncates x to n bytes and places the rest in y (if y is not NULL) */

void OCTET_CHOP(octet *x,int n,octet *y)
{
    int i;
    if (n>=x->len)
    {
        if (y!=NULL) y->len=0;
        return;
    }
    if (y!=NULL) y->len=x->len-n;
    x->len=n; 

    if (y!=NULL)
    {
        for (i=0;i<y->len && i<y->max;i++) y->val[i]=x->val[i+n];
    }
}
