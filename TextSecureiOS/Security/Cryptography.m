//
//  Cryptography.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/26/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "Cryptography.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonHMAC.h>

#import "NSData+Conversion.h"
#import "KeychainWrapper.h"
#import "Constants.h"
#import <RNCryptor/RNEncryptor.h>
#import <RNCryptor/RNDecryptor.h>
#import <RNCryptor/RNCryptorEngine.h>
#import <RNCryptor/RNCryptor.h>
#import <RNCryptor/RNCryptor+Private.h>
#include "NSString+Conversion.h"
#include "NSData+Base64.h"
#import "FilePath.h"


@implementation Cryptography


+(NSString*) generateNewAccountAuthenticationToken {
  NSMutableData* authToken = [Cryptography generateRandomBytes:16];
  NSString* authTokenPrint = [[NSData dataWithData:authToken] hexadecimalString];
  return authTokenPrint;
}

+(NSString*) generateNewSignalingKeyToken {
   /*The signalingKey is 32 bytes of AES material (256bit AES) and 20 bytes of Hmac key material (HmacSHA1) concatenated into a 52 byte slug that is base64 encoded. */
  NSMutableData* signalingKeyToken = [Cryptography generateRandomBytes:52];
  NSString* signalingKeyTokenPrint = [[NSData dataWithData:signalingKeyToken] base64EncodedString];
  return signalingKeyTokenPrint;

}


+(NSMutableData*) generateRandomBytes:(int)numberBytes {
  NSMutableData* randomBytes = [NSMutableData dataWithLength:numberBytes];
  int err = 0;
  err = SecRandomCopyBytes(kSecRandomDefault,numberBytes,[randomBytes mutableBytes]);
  if(err != noErr) {
    @throw [NSException exceptionWithName:@"random problem" reason:@"problem generating the random " userInfo:nil];
  }
  return randomBytes;
}



#pragma mark Authentication Token

+ (BOOL) storeAuthenticationToken:(NSString*)token {
  return [KeychainWrapper createKeychainValue:token forIdentifier:authenticationTokenStorageId];
}


+ (NSString*) getAuthenticationToken {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:authenticationTokenStorageId];
}

#pragma mark Username (Phone number)

+ (BOOL) storeUsernameToken:(NSString*)token {
  return [KeychainWrapper createKeychainValue:token forIdentifier:usernameTokenStorageId];
}

+ (NSString*) getUsernameToken {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:usernameTokenStorageId];
}

#pragma mark Authorization Token

+ (NSString*) getAuthorizationToken {
    return [self getAuthorizationTokenFromAuthToken:[Cryptography getAuthenticationToken]];
}

+ (NSString*) getAuthorizationTokenFromAuthToken:(NSString*)authToken{
    return [NSString stringWithFormat:@"%@:%@",[Cryptography getUsernameToken],[Cryptography getAuthenticationToken]];
}

#pragma mark SignalingKey

+ (BOOL) storeSignalingKeyToken:(NSString*)token {
    return [KeychainWrapper createKeychainValue:token forIdentifier:signalingTokenStorageId];
}

+ (NSString*) getSignalingKeyToken {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:signalingTokenStorageId];
}


+ (NSData*)computeMACDigestForString:(NSString*)input withSeed:(NSString*)seed {
  //  void CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength, const void *data,
  //       size_t dataLength, void *macOut);
  const char *cInput = [input UTF8String];
  const char *cSeed = [seed UTF8String];
  unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA1, cSeed, strlen(cSeed), cInput,strlen(cInput),cHMAC);
  NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
  return HMAC;
  
}
+ (NSString*)computeSHA1DigestForString:(NSString*)input {
  // Here we are taking in our string hash, placing that inside of a C Char Array, then parsing it through the SHA1 encryption method.
  const char *cstr = [input cStringUsingEncoding:NSUTF8StringEncoding];
  NSData *data = [NSData dataWithBytes:cstr length:input.length];
  uint8_t digest[CC_SHA1_DIGEST_LENGTH];
  
  CC_SHA1(data.bytes, data.length, digest);
  
  NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
  
  for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
    [output appendFormat:@"%02x", digest[i]];
  }
  
  return output;
}

+(NSString*)truncatedSHA1Base64EncodedWithoutPadding:(NSString*)string{
    
    NSMutableData *hashData = [NSMutableData dataWithLength:20];
    CC_SHA1([[string dataUsingEncoding:NSUTF8StringEncoding] bytes], [[string dataUsingEncoding:NSUTF8StringEncoding] length], [hashData mutableBytes]);
    NSData *truncatedData = [hashData subdataWithRange:NSMakeRange(0, 10)];

    return [[truncatedData base64EncodedString] stringByReplacingOccurrencesOfString:@"=" withString:@""];
}



+(NSData*) AES256Encryption:(NSData*) dataToEncrypt withPassword:(NSString*)password {
 // Encrypted NSData contains including a header, encryption salt, HMAC salt, IV, ciphertext, and HMAC.
  // the password is stretched via PBKDF2; using library to simplify
  NSError *error;
  NSData *encryptedData = [RNEncryptor encryptData:dataToEncrypt
                                      withSettings:kRNCryptorAES256Settings
                                          password:password
                                             error:&error];
  return encryptedData;
}
          

+(NSData*) AES256Decryption:(NSData*) dataToDecrypt withPassword:(NSString*)password {
  // Decrypts an NSData object containing including a header, encryption salt, HMAC salt, IV, ciphertext, and HMAC.
  // the password is stretched via PBKDF2
  NSError *error;
  NSData *decryptedData  = [RNDecryptor decryptData:dataToDecrypt
                                       withPassword:password
                                              error:&error];
  if(!error) {
    return decryptedData;
   
  }
  else {
     return nil;
  }
  
}

+(NSData*) truncatedHmacSHA256:(NSData*)dataToHmac withMacKey:(NSData*)hmacKey {
  uint8_t ourHmac[CC_SHA256_DIGEST_LENGTH] = {0};
  CCHmac(kCCHmacAlgSHA256,
         [hmacKey bytes],
         [hmacKey length],
         [dataToHmac bytes],
         [dataToHmac  length],
         ourHmac);
  return [NSData dataWithBytes: ourHmac length: 10];
}


+(NSData*) CC_AES256_CBC_Decryption:(NSData*) dataToDecrypt withKey:(NSData*) key withIV:(NSData*) iv withVersion:(NSData*)version withMacKey:(NSData*) hmacKey forMac:(NSData *)hmac{
  NSMutableData *dataToHmac = [NSMutableData data ];
  [dataToHmac appendData:version];
  [dataToHmac appendData:iv];
  [dataToHmac appendData:dataToDecrypt];


  NSData* ourHmacData = [Cryptography truncatedHmacSHA256:dataToHmac withMacKey:hmacKey];
  if(![ourHmacData isEqualToData:hmac]) {
    return nil;
  }

  // Decrypt
  size_t bufferSize           = [dataToDecrypt length] + kCCBlockSizeAES128;
  void* buffer                = malloc(bufferSize);
  
  size_t bytesDecrypted    = 0;
  CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                        [key bytes], [key length],
                                        [iv bytes],
                                        [dataToDecrypt bytes], [dataToDecrypt length],
                                        buffer, bufferSize,
                                        &bytesDecrypted);
  if (cryptStatus == kCCSuccess) {
    //the returned NSData takes ownership of the buffer and will free it on deallocation
    return [NSData dataWithBytesNoCopy:buffer length:bytesDecrypted];
  }

  
  
  free(buffer); //free the buffer;
  return nil;


}


+(NSData*)CC_AES256_CBC_Encryption:(NSData*) dataToEncrypt withKey:(NSData*) key withIV:(NSData*) iv withVersion:(NSData*)version  withMacKey:(NSData*) hmacKey computedMac:(NSData**)hmac {
  
  size_t bufferSize           = [dataToEncrypt length] + kCCBlockSizeAES128;
  void* buffer                = malloc(bufferSize);
  
  size_t bytesEncrypted    = 0;
  CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                        [key bytes], [key length],
                                        [iv bytes], /* initialization vector (optional) */
                                        [dataToEncrypt bytes], [dataToEncrypt length],
                                        buffer, bufferSize, /* output */
                                        &bytesEncrypted);
#warning totally insecure we need to compute hmac
  if (cryptStatus == kCCSuccess){
    //the returned NSData takes ownership of the buffer and will free it on deallocation
    NSData* encryptedData= [NSData dataWithBytesNoCopy:buffer length:bytesEncrypted];
    NSMutableData *dataToHmac = [NSMutableData data ];
    [dataToHmac appendData:version];
    [dataToHmac appendData:iv];
    [dataToHmac appendData:encryptedData];


    *hmac = [Cryptography truncatedHmacSHA256:dataToHmac withMacKey:hmacKey];
    return encryptedData;
  }
  
  free(buffer); //free the buffer;
  return nil;

}







@end
