//
//  CryptographyTests.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 12/19/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "Cryptography.h"
#import "NSData+Base64.h"
#import "NSString+Conversion.h"
#import "IncomingPushMessageSignal.hh"

@interface CryptographyTests : XCTestCase

@end


#warning this is out of date.

@implementation CryptographyTests

-(void) testLocalDecryption {
   NSString* originalMessage = @"Hawaii is awesome";
  NSString* signalingKeyString = @"VJuRzZcwuY/6VjGw+QSPy5ROzHo8xE36mKwHNvkfyZ+mSPaDlSDcenUqavIX1Vwn\nRRIdrg==";
  NSData* signalingKey = [NSData dataFromBase64String:signalingKeyString];
  XCTAssertTrue([signalingKey length]==52, @"signaling key is not 52 bytes but %d",[signalingKey length]);
  NSData* signalingKeyAESKeyMaterial = [signalingKey subdataWithRange:NSMakeRange(0, 32)];
  NSData* signalingKeyHMACKeyMaterial = [signalingKey subdataWithRange:NSMakeRange(32, 20)];
  NSData* iv = [Cryptography generateRandomBytes:16];
  NSData* version = [Cryptography generateRandomBytes:1];
  NSData* mac;
  //Encrypt

  NSData* encryption = [Cryptography CC_AES256_CBC_Encryption:[originalMessage dataUsingEncoding:NSASCIIStringEncoding] withKey:signalingKeyAESKeyMaterial withIV:iv withVersion:version withMacKey:signalingKeyHMACKeyMaterial computedMac:&mac]; //Encrypt
  
  NSMutableData *dataToHmac = [NSMutableData data ];
  [dataToHmac appendData:version];
  [dataToHmac appendData:iv];
  [dataToHmac appendData:encryption];

  
  NSData* expectedHmac = [Cryptography truncatedHmacSHA256:dataToHmac withMacKey:signalingKeyHMACKeyMaterial];
  XCTAssertTrue([mac isEqualToData:expectedHmac], @"Hmac of encrypted data %@,  not equal to expected hmac %@", [mac base64EncodedString], [expectedHmac base64EncodedString]);
  
  NSData* decryption=[Cryptography CC_AES256_CBC_Decryption:encryption withKey:signalingKeyAESKeyMaterial withIV:iv withVersion:version withMacKey:signalingKeyHMACKeyMaterial forMac:mac];
  NSString* decryptedMessage = [[NSString alloc] initWithData:decryption encoding:NSASCIIStringEncoding];
  XCTAssertTrue([decryptedMessage isEqualToString:originalMessage],  @"Decrypted message: %@ is not equal to original: %@",decryptedMessage,originalMessage);
  
}
-(void) testDecryptionFromServer {
  // we are going to want to use kCCModeCTR instead of kCCModeCBC... may need to change settings as well.
  NSString* originalMessage = @"Hawaii is awesome";
  NSString* signalingKeyString = @"VJuRzZcwuY/6VjGw+QSPy5ROzHo8xE36mKwHNvkfyZ+mSPaDlSDcenUqavIX1Vwn\nRRIdrg==";
  NSData* signalingKey = [NSData dataFromBase64String:signalingKeyString];
  NSLog(@"signaling key %@",[Cryptography getSignalingKeyToken]);
  XCTAssertTrue([signalingKey length]==52, @"signaling key is not 52 bytes but %d",[signalingKey length]);
  NSString* tsServerResponse = @"Aexen2G8XJxCxN9fp6pcCAgepw3dhoGvP1w66L560Z4BKjnh8vInFnde0pPAJe/0y07EyrQwDI9ETGyPM9D3qT5wRu3Y7UWe4J3l";
  NSData *payload = [NSData dataFromBase64String:tsServerResponse];
  unsigned char version[1];
  unsigned char iv[16];
  int ciphertext_length=([payload length]-10-17)*sizeof(char);
  unsigned char *ciphertext =  (unsigned char*)malloc(ciphertext_length);
  unsigned char mac[10];
  [payload getBytes:version range:NSMakeRange(0, 1)];
  [payload getBytes:iv range:NSMakeRange(1, 16)];
  [payload getBytes:ciphertext range:NSMakeRange(17, [payload length]-10-17)];
  [payload getBytes:mac range:NSMakeRange([payload length]-10, 10)];
  
  NSData* signalingKeyAESKeyMaterial = [signalingKey subdataWithRange:NSMakeRange(0, 32)];
  NSData* signalingKeyHMACKeyMaterial = [signalingKey subdataWithRange:NSMakeRange(32, 20)];
  NSData* decryption=[Cryptography CC_AES256_CBC_Decryption:[NSData dataWithBytes:ciphertext length:ciphertext_length] withKey:signalingKeyAESKeyMaterial withIV:[NSData dataWithBytes:iv length:16] withVersion:[NSData dataWithBytes:version length:1] withMacKey:signalingKeyHMACKeyMaterial forMac:[NSData dataWithBytes:mac length:10]];
  NSLog(@"length of decryption %d",[decryption length]);
  // Now get the protocol buffer message out
  textsecure::IncomingPushMessageSignal *fullMessageInfoRecieved = [IncomingPushMessageSignal getIncomingPushMessageSignalForData:decryption];
  
   NSString *decryptedMessage = [IncomingPushMessageSignal getMessageBody:fullMessageInfoRecieved];
   XCTAssertTrue([decryptedMessage isEqualToString:originalMessage], @"Decrypted message: %@ is not equal to original: %@",decryptedMessage,originalMessage);

}



@end

