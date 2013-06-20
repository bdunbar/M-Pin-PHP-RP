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

/*! \file  TestToken.java
    \brief An example of how to create and verify an Authentication Token

*-  Project     : MPin
*-  Authors     : Kealan McCusker
*-  Company     : Certivox
*-  Created     : 17/06/2013
*-  Last update : 
*-  Platform    : Linux (3.5)
*-  Dependency  : Miracl

    An example of how to create and verify an Authentication Token

*/

<?php

include "eccsi.php";
include "aesGcm.php";
include "sakke.php";

$rtn=0;
$fail=0;

// ECCSI Parameters 
$EGS=32; /* ECCSI Group Size */
$EFS=32; /* ECCSI Field Size */
$date=0;
$TPE=1; /* Time Permits Enabled */
$TP = pack("C*", 0x00);
for($i = strlen($TP); $i < 2*$EFS+$EGS+1; $i++) {
    $TP .= pack("C*", 0x00);
}
$SIGNATURE = pack("C*", 0x00);
for($i = strlen($SIGNATURE); $i < 2*$EGS+2*$EFS+1; $i++) {
    $SIGNATURE .= pack("C*", 0x00);
}

// AES-GCM Parameters 
$AS=16; /* Key size */  
$IVLength = 12;

// SAKKE Parameters
$SAS=16; /* Symmetric Key size - 128 bits */
$SGS=32; /* SAKKE Group Size */
$SFS=32; /* SAKKE Field Size */
$G1S=2*$SFS+1; /* Group 1 Size */
$G2S=4*$SFS; /* Group 2 Size */

// Load secrets and constant values
$KPAKHex = "04b709857b135f7856bfb6824ec95a80d8ba3046576eb1a2544654086c0439d11765bcac23b2cf3eecb868d19402030b9025f4a45b1a3672fbae340bd900312502";
$ZSHex = "0401be8a809ca50ce7aaefe7c30f3eaf6c1747499510f12d6120e7774eeeaa634805b923f47653f88b86bb303dcf8032c5352aaa39eaf35f47d14f3bf90a57f28b";
$KbSHex = "0eb5ee06823c210e6479355041c53025528493cc114b8151daeb88901351bd7818589e87e254470633e277ecf615fe1154f2ea382b9f31afe11fb6087bb85950134509be18a117e91a603d78922f761a4ecb9655742d745ea4470f1b6f84ab151318851756d729df83edec87a5de99ede437be64b2ccc5afde2998a70ea78e3c";
$PVTSSKHex = "0498ec89ea8da636495d9c9b67f814dfed82d2899d0bf95769c0541ebbe9a1ad384f816c0c97859f55c340232b87f805f7945d2c6e90d93e6d1455bd8ea5809ef4e5adb35b600f58850373957e1dd9ae143a96de85ab7c736b5076ada9f4c3a864";
$seedValueHex = "3ade3d4a5c698e8910bf92f25d97ceeb7c25ed838901a5cb5db2cf25434c1fe76c7f79b7af2e5e1e4988e4294dbd9bd9fa3960197fb7aec373609fb890d74b16a4b14b2ae7e23b75f15d36c21791272372863c4f8af39980283ae69a79cf4e48e908f9e0";
$customerID = "2ac8abba7efa09c2b0c3b760742ef2";
$endUserID    = "testUser";
$successCode = 1;
$expires = "2013-12-12T00:00:00Z";

$KPAK = hex2bin($KPAKHex);     
$ZS = hex2bin($ZSHex);     
$KbS = hex2bin($KbSHex);     
$PVTSSK = hex2bin($PVTSSKHex);     
$seedValue = hex2bin($seedValueHex); 

/* Validate Recipient Secret Key */
$rtn = validateRSK($ZS, $customerID, strlen($customerID), $KbS);
if ($rtn != 0)
  {
    print "FAILURE: validateRSK rtn: $rtn\n";
    $fail++;
  }
else
  {
    print "SUCCESS: Recipient SAKKE Secret Key is valid \n";
  }

// Token structure
class Token {
  public $endUserID;
  public $successCode;
  public $expires;
  public $signature;
}

// Encrypted Token structure
class EncryptedToken {
  public $iv;
  public $ciphertext;
  public $tag;
  public $HRbS;
}

////////////  Tasks performed by MPinAuthentication Server  ///////////////

print "Tasks performed by MPinAuthentication Server ";

// Generate a signature of token value fields
$TPE=0;
$stringToSign = $endUserID.$successCode.$expires;
print "MPinAuthentication stringToSign: $stringToSign \n";
generateSeedValue($seedValue, strlen($seedValue));
$rtn = createSignature($TPE, $stringToSign, strlen($stringToSign), $customerID, strlen($customerID), $KPAK, $PVTSSK, $TP, $SIGNATURE, $seedValue);
if ($rtn != 0)
  {
    print "MPinAuthentication FAILURE: createSignature rtn: $rtn";
    $fail++;    
  }
$SIGNATUREHex = bin2hex($SIGNATURE);

// Form token
$token = new Token();
$token->endUserID = $endUserID;
$token->successCode = $successCode;
$token->expires = $expires;
$token->signature = $SIGNATUREHex;


// JSON encode
$signedToken = json_encode($token);
print "MPinAuthentication Unencrypted Token $signedToken \n\n";

// Encrypt token
$header = "";
$ciphertext = pack( "C*", 0x00 );
for ($i = strlen($ciphertext) ; $i < strlen($signedToken) ; $i++ )
{
  $ciphertext .= pack( "C*", 0x00 );
}
// Generate AES-GCM Key
$SSV = pack("C*", 0x00);
for($i = strlen($SSV); $i < $AS; $i++) {
    $SSV .= pack("C*", 0x00);
}
aesGcm::generateSeedValue( $seedValue, strlen($seedValue) );
aesGcm::generateAESKey( $SSV, $seedValue );

// Initialisation vector
$IV = pack( "C*", 0xff );
for ($i = strlen($IV) ; $i < $IVLength ; $i++ )
{
  $IV .= pack( "C*", 0x00 );
}
aesGcm::generateSeedValue( $seedValue, strlen($seedValue) );
aesGcm::generateAESKey( $IV, $seedValue );

// Check sum
$tag = pack( "C*", 0x00 );
for ($i = strlen($tag) ; $i < $AS ; $i++ )
{
  $tag .= pack( "C*", 0x00 );
}
$rtn = aesGcmEncrypt($SSV,  $IV,  $header, strlen($header), $signedToken, strlen($signedToken), $ciphertext, $tag);
if ($rtn != 0)
  {
    print "MPinAuthentication FAILURE: aesGcmEncrypt rtn: $rtn";        
    $fail++;
  }

// Encapsulate the AES Key
$HRbS = pack( "C*", 0x00 );
for ($i = strlen($HRbS) ; $i < $G1S + $SAS ; $i++ )
{
  $HRbS .= pack( "C*", 0x00 );
}
$TPE=0;
$rtn = encapsulateSSV($SSV, $ZS, $TPE, $customerID, strlen($customerID), $HRbS);
if ($rtn != 0)
  {
    print "MPinAuthentication FAILURE: encapsulateSSV rtn: $rtn";
    $fail++;
  }

// Encrypted Token structure
$ivHex = bin2hex($IV);
$ciphertextHex = bin2hex($ciphertext);
$tagHex = bin2hex($tag);
$HRbSHex = bin2hex($HRbS);
$encryptedToken = new EncryptedToken();
$encryptedToken->iv = $ivHex;
$encryptedToken->ciphertext = $ciphertextHex;
$encryptedToken->tag = $tagHex;
$encryptedToken->HRbS = $HRbSHex;

// JSON encode
$encryptedTokenJSON = json_encode($encryptedToken);
print "MPinAuthentication Encrypted Token $encryptedTokenJSON \n\n";

////////////////// Tasks performed by MPinRP Server ////////////////////////

print "Tasks performed by MPinRP Server \n\n";

//  Decode JSON
$encryptedTokenReceived = json_decode($encryptedTokenJSON);
$ivReceivedHex = $encryptedTokenReceived->iv;
$ciphertextReceivedHex = $encryptedTokenReceived->ciphertext;
$tagReceivedHex  = $encryptedTokenReceived->tag;
$HRbSReceivedHex = $encryptedTokenReceived->HRbS;
$ivReceived = hex2bin($ivReceivedHex);  
$ciphertextReceived = hex2bin($ciphertextReceivedHex);  
$tagReceived = hex2bin($tagReceivedHex);  
$HRbSReceived = hex2bin($HRbSReceivedHex);  
print "MPinRP iv $ivReceivedHex \n"; 
print "MPinRP ciphertext ciphertextReceivedHex \n"; 
print "MPinRP tag $tagReceivedHex \n"; 
print "MPinRP HRbS $HRbSReceivedHex \n"; 

// Decapsulate the AES Key
$TPE=0;
$SSVReceived = pack("C*", 0x00);
for($i = strlen($SSVReceived); $i < $AS; $i++) {
    $SSVReceived .= pack("C*", 0x00);
}
$TPSAKKE = pack("C*", 0x00);
for($i = strlen($TPSAKKE); $i < $G2S; $i++) {
    $TPSAKKE .= pack("C*", 0x00);
}
$rtn = decapsulateSSV($HRbSReceived, $ZS, $TPE, $customerID, strlen($customerID), $KbS, $TPSAKKE, $SSVReceived);
if ($rtn != 0)
  {
    print "MPinRP FAILURE: decapsulateSSV rtn: $rtn \n";
    $fail++;
  }
print "SSV Sent: 0x".bin2hex($SSV)."\n";
print "SSV Received: 0x".bin2hex($SSVReceived)."\n\n";

// Decrypt Token
$decryptedToken = pack("C*", 0x00);
for($i = strlen($decryptedToken); $i < strlen($ciphertextReceived); $i++) {
   $decryptedToken .= pack("C*", 0x00);
}
// Check sum
$newTag = pack( "C*", 0x00 );
for ($i = strlen($newTag) ; $i < $AS ; $i++ )
{
  $newTag .= pack( "C*", 0x00 );
}
$rtn = aesGcmDecrypt($SSVReceived, $ivReceived,  $header, strlen($header), $ciphertextReceived, strlen($ciphertextReceived), $decryptedToken, $newTag);
if ($rtn != 0)
  {
    print "MPinRP FAILURE: aesGcmDecrypt rtn: $rtn";        
    $fail++;
  }

/* Compare newTag to transmitted tag - must be the same */
if ($tagReceived != $newTag)
  {
    print "FAILURE: Tag is not correct.\n";
    $fail++;
  }

print "MPinRP Decrypted Token $decryptedToken \n";

//Decode JSON
$receivedToken = json_decode($decryptedToken);
$endUserIDReceived = $receivedToken->endUserID;
$successCodeReceived = $receivedToken->successCode;
$expiresReceived = $receivedToken->expires;
$signatureReceivedHex = $receivedToken->signature;
$signatureReceived = hex2bin($signatureReceivedHex);  

// Verifiy signature
$stringToVerify = $endUserIDReceived.$successCodeReceived.$expiresReceived;
$rtn = verifySignature($TPE, $stringToVerify, strlen($stringToVerify), $customerID, strlen($customerID), $KPAK, $signatureReceived);
if ($rtn != 0)
  {
    print "NO TIME PERMITS FAILURE: verifySignature rtn: $rtn \n";        
    $fail++;
  }
else
  {
    print "SIGNATURE VERIFIED\n"; 
    if ($successCodeReceived == 1)
      {
        print "User $endUserIDReceived is authenticated\n";       
      }
    else
      {
        print "User $endUserIDReceived is not authenticated\n";       
      }
          
  }

if ($fail != 0)
  {
    print "TEST FAILED\n";
  }
else 
  {
    print "TEST PASSED\n";
  }
?>