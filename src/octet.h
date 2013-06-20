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


#ifndef OCTET_H
#define OCTET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* portable representation of a big positive number */

typedef struct
{
    int len;
    int max;
    char *val;
} octet;

/* Octet string handlers */

extern void OCTET_OUTPUT(octet *);
extern void OCTET_OUTPUT_STRING(octet *);
extern void OCTET_CLEAR(octet *);
extern int  OCTET_COMPARE(octet *,octet *);
extern void OCTET_JOIN_STRING(char *,octet *);
extern void OCTET_JOIN_BYTES(char *,int,octet *);
extern void OCTET_JOIN_BYTE(int,int,octet *);
extern void OCTET_JOIN_OCTET(octet *,octet *);
extern void OCTET_XOR(octet *,octet *);
extern void OCTET_EMPTY(octet *);
extern void OCTET_PAD(int,octet *);
extern void OCTET_TO_BASE64(octet *,char *);
extern void OCTET_FROM_BASE64(char *,octet *);
extern void OCTET_COPY(octet *,octet *);
extern void OCTET_XOR_BYTE(int,octet *);
extern void OCTET_CHOP(octet *,int,octet *);
extern void OCTET_JOIN_LONG(long,int,octet *);

#endif
