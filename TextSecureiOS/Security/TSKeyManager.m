//
//  TSKeyManager.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 12/1/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSKeyManager.h"
#import "TSEncryptedDatabase+Private.h"
#import "ECKeyPair.h"
#import "Cryptography.h"
#import "KeychainWrapper.h"
#import "NSData+Base64.h"
#import "NSData+Conversion.h"
#import "TSRegisterPrekeysRequest.h"
#import "TSEncryptedDatabaseError.h"
@implementation TSKeyManager

+ (BOOL) generateCryptographyKeysForNewUser {
  [TSKeyManager generateAndStoreIdentityKey];
  [TSKeyManager generateAndStoreNewPreKeys:70];
  return YES;
}




+(void) generateAndStoreIdentityKey {
  /*
   An identity key is an ECC key pair that you generate at install time. It never changes, and is used to certify your identity (clients remember it whenever they see it communicated from other clients and ensure that it's always the same).
   
   In secure protocols, identity keys generally never actually encrypt anything, so it doesn't affect previous confidentiality if they are compromised. The typical relationship is that you have a long term identity key pair which is used to sign ephemeral keys (like the prekeys).
   */
  TSEncryptedDatabase *cryptoDB = [TSEncryptedDatabase database];
  ECKeyPair *identityKey = [ECKeyPair createAndGeneratePublicPrivatePair:-1];
  [cryptoDB storeIdentityKey:identityKey];
  
}

+(void) generateAndStoreNewPreKeys:(int)numberOfPreKeys{
#warning generateAndStoreNewPreKeys not yet tested
  TSEncryptedDatabase *cryptoDB = [TSEncryptedDatabase database];
  int lastPrekeyCounter = [cryptoDB getLastPrekeyId];
  NSMutableArray *prekeys = [[NSMutableArray alloc] initWithCapacity:numberOfPreKeys];
  if(lastPrekeyCounter<0) {
    // Prekeys have never before been generated
    lastPrekeyCounter = arc4random() % 16777215; //16777215 is 0xFFFFFF
    [prekeys addObject:[ECKeyPair createAndGeneratePublicPrivatePair:16777215]]; // Key of last resoort
  }
  
  
  for( int i=0; i<numberOfPreKeys; i++) {
    [prekeys addObject:[ECKeyPair createAndGeneratePublicPrivatePair:++lastPrekeyCounter]];
  }
  [cryptoDB savePersonalPrekeys:prekeys];
  // Sending new prekeys to network
  [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSRegisterPrekeysRequest alloc] initWithPrekeyArray:prekeys identityKey:[cryptoDB getIdentityKey]] success:^(AFHTTPRequestOperation *operation, id responseObject) {
    
    switch (operation.response.statusCode) {
      case 200:
      case 204:
        DLog(@"Device registered prekeys");
        break;
        
      default:
        DLog(@"Issue registering prekeys response %d, %@",operation.response.statusCode,operation.response.description);
#warning Add error handling if not able to send the prekeys
        break;
    }
  } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
#warning Add error handling if not able to send the token
    DLog(@"failure %d, %@",operation.response.statusCode,operation.response.description);
    
    
  }];
  
  
}


+(NSData*) generateDatabaseMasterKeyWithPassword:(NSString*) userPassword {
  NSData *encryptedDbMasterKey = [Cryptography generateKeyForPassword:userPassword];
  if(!encryptedDbMasterKey) {
    // TODO: Can we really recover from this ? Maybe we should throw an exception
    //@throw [NSException exceptionWithName:@"DB creation failed" reason:@"could not generate a master key" userInfo:nil];
    return nil;
  }
  
  if (![KeychainWrapper createKeychainValue:[encryptedDbMasterKey base64EncodedString] forIdentifier:encryptedMasterSecretKeyStorageId]) {
    // TODO: Can we really recover from this ? Maybe we should throw an exception
    //@throw [NSException exceptionWithName:@"keychain error" reason:@"could not write DB master key to the keychain" userInfo:nil];
    return nil;
  }
  return encryptedDbMasterKey;
}



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
  return [self getAuthorizationTokenFromAuthToken:[TSKeyManager getAuthenticationToken]];
}

+ (NSString*) getAuthorizationTokenFromAuthToken:(NSString*)authToken{
  NSLog(@"Username : %@ and AuthToken: %@", [TSKeyManager getUsernameToken], [TSKeyManager getAuthenticationToken] );
  return [NSString stringWithFormat:@"%@:%@",[TSKeyManager getUsernameToken],[TSKeyManager getAuthenticationToken]];
}



#pragma mark SignalingKey

+ (BOOL) storeSignalingKeyToken:(NSString*)token {
  return [KeychainWrapper createKeychainValue:token forIdentifier:signalingTokenStorageId];
}

+ (NSString*) getSignalingKeyToken {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:signalingTokenStorageId];
}

#pragma mark Database encryption master key - private






+ (NSData*) getDatabaseMasterKeyWithPassword:(NSString*) userPassword error:(__autoreleasing NSError**) error {
  NSString *encryptedDbMasterKey = [KeychainWrapper keychainStringFromMatchingIdentifier:encryptedMasterSecretKeyStorageId];
  if (!encryptedDbMasterKey) {
    *error = [TSEncryptedDatabaseError dbWasCorrupted];
    return nil;
  }
  return [NSData dataFromBase64String:encryptedDbMasterKey];
}


 +(NSData*) validateKey:(NSString*)encryptedKey forPassword:(NSString*) password error:(__autoreleasing NSError**) error{
  
   NSData *dbMasterKey = [Cryptography decryptKey:encryptedKey withPassword:password error:error];
   if (error) {
     // Wrong password; clarify the error returned
     *error = [TSEncryptedDatabaseError invalidPassword];
     return nil;
   }
   return dbMasterKey;
   
 }

 
 
+(void) eraseDatabaseMasterKey {
  [KeychainWrapper deleteItemFromKeychainWithIdentifier:encryptedMasterSecretKeyStorageId];
}





@end
