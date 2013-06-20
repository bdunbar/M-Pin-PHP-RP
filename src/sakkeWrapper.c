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
/*! \file  sakkeWrapper.c
    \brief Definitions for the SAKKE algorithm wrappers

*-  Project     : MPin
*-  Authors     : Kealan McCusker
*-  Company     : Certivox
*-  Created     : 08/11/2012
*-  Last update : 20/03/2013
*-  Platform    : Linux (3.5)
*-  Dependency  : Miracl

    Provides an API for the SAKKE algorithm

*/

/* #define DEBUG */
/* #define TEST  */

#include "sakkeWrapper.h"

/*! \brief Generate today's date for use in Time Permit generation
 *
 *  Generates todays date. Format is 24 bits: year (12 bits) | day_of_month (5 bits) | month (4 bits) | weekday (3 bits) 
 * 
 *  @return rtn   Returns todays date. Format is 24 bits: year (12 bits) | day_of_month (5 bits) | month (4 bits) | weekday (3 bits) 
 */
int todaySAKKE(void)
{
  int rtn=0;
  rtn = today();

#ifdef DEBUG
  printf("todaySAKKE: date: %d \n", rtn);
#endif

  return rtn;
}

/*! \brief Encapsulate the Shared Secret Value (SSV)
 *
 *  The \f$ R_{(b,S)} \f$ and H values are calculated using these steps;
 *  <ol>
 *  <li> Compute r = HashToIntegerRange( SSV || b, q, Hash );
 *  <li> Compute \f$ R_{(b,S)} = [r]([b]P + Z_S) \f$ in \f$ E(F_p) \f$;
 *  <li> Compute the Hint, H;
 *  <ul>
 *      <li> Compute \f$ g^r \f$. 
 *      <li> Compute H := SSV XOR HashToIntegerRange( \f$ g^r \f$, \f$ 2^n \f$, Hash );
 *  </ul>
 *  <li> Return the Encapsulated Data (  H, \f$ R_{(b,S)} \f$ )
 *  </ol>
 *
 *  @param  SSV       Shared Secret Value    
 *  @param  ZS        Public key of \f$ KMS_S \f$ equates to \f$ Z_S \f$ in the preceding text
 *  @param  TPE       Time permit enabled 1: Use Time Permits 0: Do not use Time Permits
 *  @param  ID        The identity of the receiving party equates to b in the preceding text
 *  @param  IDLength  The length of the identity in bytes
 *  @return HRbS      Equates to (  H, \f$ R_{(b,S)} \f$ )||Date
 *  @return           Returns 0 if successful or else an error code  
 */
int encapsulateSSV(char* SSV, char* ZS, int TPE, char* ID, int IDLength, char* HRbS)
{
  octet octetSSV={SAS,SAS,SSV};
  octet octetZS={G1S,G1S,ZS};
  octet octetID={IDLength,IDLength,ID};
  octet octetHRbS={G1S+SAS,G1S+SAS,HRbS};
  if (TPE == 1)
    {
      octetHRbS.len = G1S+SAS+4;
      octetHRbS.max = G1S+SAS+4;
    }
  sak_domain skdom;
  int rtn=0;

#ifdef DEBUG
  printf("encapsulateSSV: TPE: %d \n", TPE);
  printf("encapsulateSSV: octetHRbS.len: %d \n", octetHRbS.len);
  printf("encapsulateSSV: octetHRbS.max: %d \n", octetHRbS.max);
  printf("encapsulateSSV: SSV := 0x"); OCTET_OUTPUT(&octetSSV);
  printf("encapsulateSSV: ZS  := 0x"); OCTET_OUTPUT(&octetZS);
  printf("encapsulateSSV: ID  := 0x"); OCTET_OUTPUT(&octetID);
#endif

  rtn = SAKKE_DOMAIN_INIT(&skdom,skrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  rtn = SAKKE_KEY_ENCAPSULATE(&skdom,&octetSSV,&octetZS,TPE, &octetID,&octetHRbS);

#ifdef DEBUG
  printf("encapsulateSSV: HRbS := 0x"); OCTET_OUTPUT(&octetHRbS);
#endif

  SAKKE_DOMAIN_KILL(&skdom);

  return rtn;
}

/*! \brief Validate the Receiver Secret Key (RSK)
 *
 *  Upon receipt of keying material the user must verify its Receiver Secret Key (RSK).
 * 
 *  <ol>
 *  <li> Compute \f$ < [b]P + Z_S, K_{(b,S)} >\f$ If this is equal to g then output 0 else output an error code.
 *  </ol>
 *
 *  @param ZS        Public key of \f$ KMS_S \f$ equates to \f$ Z_S \f$ in the preceding text
 *  @param ID        The identity of the receiving party equates to b in the preceding text
 *  @param IDLength  The length of the identity in bytes
 *  @param KbS       The Receiver Secret Key (RSK) equates to \f$ K_{(b,S)} \f$ in the preceding text
 *  @return          Returns 0 if key is valid else an error code  
 */
int validateRSK(char* ZS, char* ID,  int IDLength, char* KbS)
{
  octet octetZS={G1S,G1S,ZS};
  octet octetID={IDLength,IDLength,ID};
  octet octetKbS={G2S,G2S,KbS};
  sak_domain skdom;
  int rtn=0;

#ifdef DEBUG
  printf("validateRSK: ZS  := 0x"); OCTET_OUTPUT(&octetZS);
  printf("validateRSK: ID  := 0x"); OCTET_OUTPUT(&octetID);
  printf("validateRSK: KbS := 0x"); OCTET_OUTPUT(&octetKbS);
#endif

  rtn = SAKKE_DOMAIN_INIT(&skdom,skrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  rtn = SAKKE_SECRET_KEY_VALIDATE(&skdom,&octetID,&octetZS,&octetKbS);

#ifdef DEBUG
  printf("validateRSK: rtn : %d\n", rtn);
#endif

  SAKKE_DOMAIN_KILL(&skdom);

  return rtn;
}


/*! \brief Validate the time permit
 *
 *  Validate the time permit by checking it is a valid point on the curve.
 *
 *  @param date      Today's date
 *  @param ID        The identity of the receiving party 
 *  @param IDLength  The length of the identity in bytes
 *  @param ZS        Public key of \f$ KMS_S \f$
 *  @param KbS       The Receiver Secret Key (RSK) 
 *  @param TP        The time permit
 *  @return          Returns 0 if time permit is valid else an error code  
 */
int validateSAKKETimePermit(int date, char* ID, int IDLength, char* ZS, char* KbS, char* TP)
{
  octet octetID={IDLength,IDLength,ID};
  octet octetZS={G1S,G1S,ZS};
  octet octetKbS={G2S,G2S,KbS};
  octet octetTP={G2S,G2S,TP};
  sak_domain skdom;
  int rtn=0;

#ifdef DEBUG
  printf("validateSAKKETimePermit: ID  := 0x"); OCTET_OUTPUT(&octetID);
  printf("validateSAKKETimePermit: ZS  := 0x"); OCTET_OUTPUT(&octetZS);
  printf("validateSAKKETimePermit: KbS := 0x"); OCTET_OUTPUT(&octetKbS);
  printf("validateSAKKETimePermit: TP  := 0x"); OCTET_OUTPUT(&octetTP);
#endif

  rtn = SAKKE_DOMAIN_INIT(&skdom,skrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  rtn = SAKKE_PERMIT_VALIDATE(&skdom, date, &octetID, &octetZS, &octetKbS, &octetTP);

  printf("validateSAKKETimePermit: rtn : %d\n", rtn);

  SAKKE_DOMAIN_KILL(&skdom);

  return rtn;
}


/*! \brief Decapsulate the Shared Secret Value (SSV)
 *
 *  Device B receives Encapsulated Data from device A. In order to
 *  process this, it requires its RSK, \f$ K_{(b,S)} \f$, which will have been
 *  provisioned in advance by \f$ KMS_S \f$. The function carries out the 
 *  following steps to derive and verify the SSV:
 * 
 *  <ol>
 *  <li> Compute \f$ w := < R_{(b,S)}, K_{(b,S)} > \f$ . Note that by bilinearity, \f$ w = g^r\f$;
 *  <li> Compute \f$ SSV = H XOR HashToIntegerRange( w, 2^n, Hash )\f$;
 *  <li> Compute \f$ r = HashToIntegerRange( SSV || b, q, Hash )\f$;
 *  <li> Compute \f$ TEST = [r]([b]P + Z_S)\f$ in \f$E(F_p)\f$. If TEST does not equal \f$R_{(b,S)}\f$, then B MUST NOT use the SSV to derive key material;
 *  <li> Output SSV for use to derive key material for the application to be keyed.
 *  </ol>
 *
 *  @param HRbS      Equates to (  H, \f$ R_{(b,S)} \f$ )||Date
 *  @param ZS        Public key of \f$ KMS_S \f$ equates to \f$ Z_S \f$ in the preceding text
 *  @param TPE       Time permit enabled 1: Use Time Permits 0: Do not use Time Permits
 *  @param ID        The identity of the receiving party equates to b in the preceding text
 *  @param IDLength  The length of the identity in bytes
 *  @param KbS       The Receiver Secret Key (RSK) equates to \f$ K_{(b,S)} \f$ in the preceding text
 *  @param TP        The time permit
 *  @return SSV      Shared Secret Value    
 *  @return          Returns 0 if successful or else an error code  
 */
int decapsulateSSV(char* HRbS, char* ZS, int TPE, char* ID, int IDLength, char* KbS, char* TP, char* SSV)
{
  octet octetZS={G1S,G1S,ZS};
  octet octetID={IDLength,IDLength,ID};
  octet octetKbS={G2S,G2S,KbS};
  octet octetTP={G2S,G2S,TP};
  octet octetSSV={SAS,SAS,SSV};
  octet octetHRbS={G1S+SAS,G1S+SAS,HRbS};
  if (TPE == 1)
    {
      octetHRbS.len = G1S+SAS+4;
      octetHRbS.max = G1S+SAS+4;
    }

  sak_domain skdom;
  int rtn=0;

#ifdef DEBUG
  printf("decapsulateSSV: TPE: %d \n", TPE);
  printf("decapsulateSSV: octetHRbS.len: %d \n", octetHRbS.len);
  printf("decapsulateSSV: octetHRbS.max: %d \n", octetHRbS.max);
  printf("decapsulateSSV: ZS  := 0x"); OCTET_OUTPUT(&octetZS);
  printf("decapsulateSSV: ID  := 0x"); OCTET_OUTPUT(&octetID);
  printf("decapsulateSSV: HRbS := 0x"); OCTET_OUTPUT(&octetHRbS);
  printf("decapsulateSSV: KbS := 0x"); OCTET_OUTPUT(&octetKbS);
  printf("decapsulateSSV: SSV (IN):= 0x"); OCTET_OUTPUT(&octetSSV);
#endif

  rtn = SAKKE_DOMAIN_INIT(&skdom,skrom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    } 

  if (TPE == 1)
    {
      rtn = SAKKE_KEY_DECAPSULATE(&skdom,&octetHRbS, &octetZS, &octetID, &octetKbS, &octetTP, &octetSSV);
#ifdef DEBUG
  printf("decapsulateSSV: TP := 0x"); OCTET_OUTPUT(&octetTP);
#endif
    }
  else
    rtn = SAKKE_KEY_DECAPSULATE(&skdom,&octetHRbS, &octetZS, &octetID, &octetKbS, NULL, &octetSSV);

#ifdef DEBUG
  printf("decapsulateSSV: SSV (OUT):= 0x"); OCTET_OUTPUT(&octetSSV);
  printf("decapsulateSSV: rtn : %d \n", rtn);
#endif

  SAKKE_DOMAIN_KILL(&skdom);

  return rtn;
}










