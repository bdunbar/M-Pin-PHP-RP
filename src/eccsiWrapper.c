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
/*! \file  eccsiWrapper.c
    \brief Definitions for the ECCSI algorithm wrappers

*-  Project     : MPin
*-  Authors     : Kealan McCusker
*-  Company     : Certivox
*-  Created     : 08/11/2012
*-  Last update : 21/03/2012
*-  Platform    : Linux (3.5)
*-  Dependency  : Miracl

    Provides an API for the ECCSI algorithm

*/

/* #define DEBUG  */

#include "eccsiWrapper.h"

/*! \brief Generate today's date for use in Time Permit generation
 *
 *  Generates todays date. Format is 24 bits: year (12 bits) | day_of_month (5 bits) | month (4 bits) | weekday (3 bits) 
 * 
 *  @return rtn   Returns todays date. Format is 24 bits: year (12 bits) | day_of_month (5 bits) | month (4 bits) | weekday (3 bits) 
 */
int todayECCSI(void)
{
  int rtn=0;
  rtn = today();

#ifdef DEBUG
  printf("todayECCSI: date: %d \n", rtn);
#endif

  return rtn;
}



/*! \brief Validate the Secret Signing Key (SSK) or the Time Permit (TP) 
 *
 *  The SSK must be validated before being used as a signing key.
 *  Thus function uses the ID and the KPAK to validate a received (SSK,PVT)
 *  pair by performing these steps:
 * 
 *  <ol>
 *  <li> Validate that the PVT lies on the elliptic curve E.
 *  <li> Compute HS = hash( G || KPAK || ID || PVT ), an N-octet integer.
 *  <li> Validate that KPAK = [SSK]G - [HS]PVT.
 *  </ol>
 *
 *  @param  date      zero means validate (SSK,PVT): A date value means validate the Time Permit
 *  @param  ID        Signer's identity
 *  @param  IDLength  The length of the identity in bytes
 *  @param  KPAK      KMS Public Authentication Key
 *  @param  PVTSSK    (PVT||SSK) or the Time Permit depending on the date
 *  @return rtn       Returns 0 if (SSK,PVT) / TP is valid or else an error code  
 */
int validateECCSIUserKey(int date, char* ID, int IDLength, char* KPAK, char* PVTSSK)
{
  octet octetID={IDLength,IDLength,ID};
  octet octetKPAK={2*EFS+1,2*EFS+1,KPAK};
  octet octetPVTSSK={2*EFS+EGS+1,2*EFS+EGS+1,PVTSSK};
  ecs_domain esdom;
  int rtn=0;

#ifdef DEBUG
  printf("validateECCSIUserKey: ID = "); OCTET_OUTPUT(&octetID);
  printf("validateECCSIUserKey: KPAK = "); OCTET_OUTPUT(&octetKPAK);
  printf("validateECCSIUserKey: PVTSSK = "); OCTET_OUTPUT(&octetPVTSSK);
#endif

  rtn = ECS_DOMAIN_INIT(&esdom,esrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  rtn = ECCSI_USER_KEY_VALIDATE(&esdom, date, &octetID,&octetKPAK,&octetPVTSSK);

#ifdef DEBUG
  printf("validateECCSIUserKey: rtn: %d \n", rtn);
#endif

  ECS_DOMAIN_KILL(&esdom);

  return rtn;
}

/*! \brief Sign a message
 *
 *  To sign a message (M), the Signer performs these steps:
 * 
 *  <ol>
 *  <li> Choose a random (ephemeral) non-zero value \f$ j \in  F_q \f$
 *  <li> Compute J = [j]G then assign to r the N-octet integer representing Jx;
 *  <li> Compute a hash value HE = hash( HS || r || M )
 *  <li> Verify that HE + r * SSK is non-zero modulo q else abort
 *  <li> Compute\f$  s' = ( (( HE + r * SSK )^{-1}) * j )\f$ modulo q; the Signer MUST 
 *       then erase the value j
 *  <li> If s' is too big to fit within an N-octet integer, then set the N-octet 
 *       integer s = q - s'; otherwise, set the N-octet integers = s'
 *  <li> Return the signature = ( r || s || PVT )
 *  </ol>
 *
 *  @param  TPE       Time Permit enable - 1: Time Permits On  0: Time Permits Off
 *  @param  M         Message to be signed
 *  @param  MLength   Message length to be signed
 *  @param  ID        Signer's identity
 *  @param  IDLength  The length of the identity in bytes
 *  @param  KPAK      KMS Public Authentication Key
 *  @param  PVTSSK    (PVT||SSK)
 *  @param  TP        Time Permit
 *  @param  seedValue 100 byte random value
 *  @return SIGNATURE The calculated signature
 *  @return rtn       Returns 0 if successful or else an error code  
 */
int createSignature(int TPE, char* M, int MLength, char* ID,  int IDLength, char* KPAK,  
                    char* PVTSSK, char* TP, char* SIGNATURE, char* seedValue)
{
  octet octetM={MLength,MLength,M};
  octet octetID={IDLength,IDLength,ID};
  octet octetKPAK={2*EFS+1,2*EFS+1,KPAK};
  octet octetPVTSSK={2*EFS+EGS+1,2*EFS+EGS+1,PVTSSK};
  octet octetTP={2*EFS+EGS+1,2*EFS+EGS+1,TP};
  octet octetSIGNATURE={2*EGS+2*EFS+1,2*EGS+2*EFS+1,SIGNATURE};
  if (TPE == 1)
    {
      octetSIGNATURE.len = 2*EGS+4*EFS+6;
      octetSIGNATURE.max = 2*EGS+4*EFS+6;
    }

  ecs_domain esdom;
  int rtn=0;
  int i=0;

  /* Only used for testing */
  char j[EGS];
  octet octetJ={sizeof(j),sizeof(j),j};
  for (i=0; i<EGS; i++)
    octetJ.val[i]=0x00;  

#ifdef DEBUG
  printf("createSignature: TPE = %d\n",TPE);
  printf("createSignature: octetSIGNATURE.len = %d\n",octetSIGNATURE.len);
  printf("createSignature: octetSIGNATURE.max = %d\n",octetSIGNATURE.max);
  printf("createSignature: M = "); OCTET_OUTPUT(&octetM);
  printf("createSignature: ID = "); OCTET_OUTPUT(&octetID);
  printf("createSignature: KPAK = "); OCTET_OUTPUT(&octetKPAK);
  printf("createSignature: PVTSSK = "); OCTET_OUTPUT(&octetPVTSSK);
#endif

  /* Initialise elliptic curve from ROM */
  rtn = ECS_DOMAIN_INIT(&esdom,esrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  /* Crypto string RNG */
  csprng RNG;
  RNG = generateRNG(seedValue);

  if (TPE == 1)
    rtn = ECCSI_SIGN(&esdom, &RNG, &octetJ, &octetM, &octetID, &octetKPAK,
                     &octetPVTSSK, &octetTP, &octetSIGNATURE);
  else
    rtn = ECCSI_SIGN(&esdom, &RNG, &octetJ, &octetM, &octetID, &octetKPAK,
                     &octetPVTSSK, NULL, &octetSIGNATURE);



#ifdef DEBUG
  printf("createSignature: J := 0x "); OCTET_OUTPUT(&octetJ);
  printf("createSignature: SIGNATURE := "); OCTET_OUTPUT(&octetSIGNATURE);
  printf("createSignature: rtn: %d \n", rtn);
#endif

  ECS_DOMAIN_KILL(&esdom);

  return rtn;
}

/*! \brief Verify the signature
 *
 * To verify a Signature ( r || s || PVT ) against a Signer's Identifier
 * (ID), a message (M), and a pre-installed root of trust (KPAK), the
 * Verifier must perform a procedure equivalent to the following:
 * 
 *  <ol>
 *  <li> Check that the PVT lies on the elliptic curve E;
 *  <li> Compute HS = hash( G || KPAK || ID || PVT );
 *  <li> Compute HE = hash( HS || r || M );
 *  <li> Y = [HS]PVT + KPAK;
 *  <li> Compute J = [s]( [HE]G + [r]Y );
 *  <li> Check that \f$ J_x \f$= r modulo p, and that \f$ J_x \f$ modulo p is non-zero,
 *       before accepting the Signature as valid.
 *  </ol>
 *
 *  @param  TPE       Time Permit enable - 1: Time Permits On  0: Time Permits Off
 *  @param  M         Message to be verified
 *  @param  MLength   Message length
 *  @param  ID        Signer's identity
 *  @param  IDLength  The length of the identity in bytes
 *  @param  KPAK      KMS Public Authentication Key
 *  @param  SIGNATURE The signature to be verified
 *  @return rtn       Returns 0 if successful or else an error code  
 */
int verifySignature(int TPE, char* M, int MLength, char* ID, int IDLength, 
                    char* KPAK, char* SIGNATURE)
{
  octet octetM={MLength,MLength,M};
  octet octetID={IDLength,IDLength,ID};
  octet octetKPAK={2*EFS+1,2*EFS+1,KPAK};
  octet octetSIGNATURE={2*EGS+2*EFS+1,2*EGS+2*EFS+1,SIGNATURE};
  if (TPE == 1)
    {
      octetSIGNATURE.len = 2*EGS+4*EFS+6;
      octetSIGNATURE.max = 2*EGS+4*EFS+6;
    }

  ecs_domain esdom;
  int rtn=0;

#ifdef DEBUG
  printf("verifySignature: TPE: %d", TPE);
  printf("verifySignature: octetSIGNATURE.len = %d\n",octetSIGNATURE.len);
  printf("verifySignature: octetSIGNATURE.max = %d\n",octetSIGNATURE.max);
  printf("verifySignature: M = "); OCTET_OUTPUT(&octetM);
  printf("verifySignature: ID = "); OCTET_OUTPUT(&octetID);
  printf("verifySignature: KPAK = "); OCTET_OUTPUT(&octetKPAK);
  printf("verifySignature: SIGNATURE = "); OCTET_OUTPUT(&octetSIGNATURE);
#endif

  /* Initialise elliptic curve from ROM */
  rtn = ECS_DOMAIN_INIT(&esdom,esrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  rtn = ECCSI_VERIFY(&esdom, TPE, &octetM, &octetID, &octetKPAK, &octetSIGNATURE);


#ifdef DEBUG
  printf("verifySignature: rtn: %d \n", rtn);
#endif

  ECS_DOMAIN_KILL(&esdom);

  return rtn;
}




