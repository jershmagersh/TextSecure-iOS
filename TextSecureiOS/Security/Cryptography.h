//
//  Cryptography.h
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/26/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Cryptography : NSObject
+(NSString*) generateNewAccountAuthenticationToken;
+(NSString*) generateNewSignalingKeyToken;

+ (BOOL) storeAuthenticationToken:(NSString*)token;
+ (NSString*) getAuthenticationToken;
+ (BOOL) storeUsernameToken:(NSString*)token;
+ (NSString*) getUsernameToken;
+ (NSString*)computeSHA1DigestForString:(NSString*)input;
+(void) generateAndStoreIdentityKey;
+ (NSData*) getMasterSecretKey:(NSString*) userPassword;
+ (void) generateAndStoreMasterSecretPassword:(NSString*) userPassword;
+(NSMutableData*) generateRandomBytes:(int)numberBytes;
+ (BOOL) storeEncryptedMasterSecretKey:(NSString*)token;
+ (NSString*) getEncryptedMasterSecretKey;
+(void) generateAndStoreNewPreKeys:(int)numberOfPreKeys;
/* 
 Basic auth is username:password base64 encoded where the "username" is the device's phone number in E164 format, and the "password" is a random string you generate at registration time.
 What we're doing is just using the Authorization header to convey that information, since it's more REST-ish. In subsequent calls, you'll authenticate with the same Authorization header.
 */
+ (NSString*) getAuthorizationToken;
+ (NSString*) getAuthorizationTokenFromAuthToken:(NSString*)authToken;
/*  The signalingKey is 32 bytes of AES material (256bit AES) and 20 bytes of Hmac key material (HmacSHA1) concatenated into a 52 byte slug that is base64 encoded.
    See   for usage, 52 random bytes generated at init which will be used as key material for AES256 (first 32 bytes) and HmacSHA1 */
+ (NSString*) getSignalingKeyToken;
+ (BOOL) storeSignalingKeyToken:(NSString*)token;

+ (NSData*)computeMACDigestForString:(NSString*)input withSeed:(NSString*)seed;
+(NSData*) AES256Encryption:(NSData*) dataToEncrypt withPassword:(NSString*)password;
+(NSData*) AES256Decryption:(NSData*) dataToDecrypt withPassword:(NSString*)password;

+(NSData*) CC_AES256_CBC_Decryption:(NSData*) dataToDecrypt withKey:(NSData*) key withIV:(NSData*) iv withMac:(NSData*)hmacKey;
+(NSString*)truncatedSHA1Base64EncodedWithoutPadding:(NSString*)string;

@end
