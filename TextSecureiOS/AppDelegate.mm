//
//  AppDelegate.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/24/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "AppDelegate.hh"
#import "Cryptography.h"
#import "UserDefaults.h"
#import <PonyDebugger/PonyDebugger.h> //ponyd serve --listen-interface=127.0.0.1
#import "NSObject+SBJson.h"
#import "TSEncryptedDatabase.h"
#import "TSEncryptedDatabaseError.h"
#import "TSRegisterForPushRequest.h"
#import "NSString+Conversion.h"
#warning remove the below imports
#import "IncomingPushMessageSignal.hh"
#import "TSContact.h"
#import "NSData+Base64.h"
#import "TSSubmitMessageRequest.h"
#import "TSMessagesManager.h"

@implementation AppDelegate

#pragma mark - UIApplication delegate methods

#define firstLaunchKey @"FirstLaunch"

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // If this is the first launch, we want to remove stuff from the Keychain that might be there from a previous install
    
    if (![[NSUserDefaults standardUserDefaults] boolForKey:firstLaunchKey]) {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:firstLaunchKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [UserDefaults removeAllKeychainItems];
        DLog(@"First Launch");
      
    }
    
#ifdef DEBUG
	[[BITHockeyManager sharedHockeyManager] configureWithBetaIdentifier:@"9e6b7f4732558ba8480fb2bcd0a5c3da"
														 liveIdentifier:@"9e6b7f4732558ba8480fb2bcd0a5c3da"
															   delegate:self];
	[[BITHockeyManager sharedHockeyManager] startManager];
    
    PDDebugger *debugger = [PDDebugger defaultInstance];
    [debugger connectToURL:[NSURL URLWithString:@"ws://localhost:9000/device"]];
    [debugger enableNetworkTrafficDebugging];
    [debugger forwardAllNetworkTraffic];
#endif
	
	if(launchOptions!=nil) {
		[self handlePush:launchOptions];
	}
	if([UserDefaults hasVerifiedPhoneNumber] && [TSEncryptedDatabase databaseWasCreated]) {
		[[UIApplication sharedApplication] registerForRemoteNotificationTypes:
		 (UIRemoteNotificationTypeBadge | UIRemoteNotificationTypeSound | UIRemoteNotificationTypeAlert)];
     UIAlertView *passwordDialogue =   [[UIAlertView alloc] initWithTitle:@"Password" message:@"enter your password" delegate:self cancelButtonTitle:@"Cancel" otherButtonTitles:@"OK", nil];
    passwordDialogue.alertViewStyle = UIAlertViewStyleSecureTextInput;

    [passwordDialogue show];
    
	}
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(sendMessage:) name:@"SendMessage" object:nil];
	return YES;

}


- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    NSError *error = nil;
#warning we will want better error handling, including reprompting if user enters password wrong
    if(buttonIndex==1) {
        NSString* password = [[alertView textFieldAtIndex:0] text];
        if (![TSEncryptedDatabase databaseUnlockWithPassword:password error:&error]) {
            if ([[error domain] isEqualToString:TSEncryptedDatabaseErrorDomain]) {
                switch ([error code]) {
                    case InvalidPassword:
                        // TODO: Proper error handling
                        @throw [NSException exceptionWithName:@"Wrong password" reason:[error localizedDescription] userInfo:nil];
                        break;
                    case NoDbAvailable:
                        // TODO: Proper error handling
                        @throw [NSException exceptionWithName:@"No DB available; create one first" reason:[error localizedDescription] userInfo:nil];
                }
            }
        }
  }
}

-(void) sendMessage:(NSNotification*)notification {
  TSContact* contact = [[notification userInfo] objectForKey:@"contact"];
  NSString *message = [[notification userInfo] objectForKey:@"message"];
  NSString *serializedMessage = [[IncomingPushMessageSignal createSerializedPushMessageContent:message withAttachments:nil] base64Encoding];
  //Tests deserialization
  NSString* deserializedMessage = [IncomingPushMessageSignal prettyPrintPushMessageContent:[IncomingPushMessageSignal getPushMessageContentForData:[NSData dataFromBase64String:serializedMessage]]];
  [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSSubmitMessageRequest alloc] initWithRecipient:contact message:serializedMessage] success:^(AFHTTPRequestOperation *operation, id responseObject) {
    
    switch (operation.response.statusCode) {
      case 200:
        DLog(@"we have some success information %@",responseObject);
        // So let's encrypt a message using this
        break;
        
      default:
        DLog(@"error sending message");
#warning Add error handling if not able to get contacts prekey
        break;
    }
  } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
#warning Add error handling if not able to send the token
    DLog(@"failure %d, %@, %@",operation.response.statusCode,operation.response.description,[[NSString alloc] initWithData:operation.responseData encoding:NSUTF8StringEncoding]);
    
    
  }];
  

}



#pragma mark - Push notifications

- (void)application:(UIApplication*)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData*)deviceToken {
	NSString *stringToken = [[deviceToken description] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
	stringToken = [stringToken stringByReplacingOccurrencesOfString:@" " withString:@""];
	
    [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSRegisterForPushRequest alloc] initWithPushIdentifier:stringToken] success:^(AFHTTPRequestOperation *operation, id responseObject) {

        switch (operation.response.statusCode) {
            case 200:
                DLog(@"Device registered for push notifications");
                break;
                
            default:
#warning Add error handling if not able to send the token
                break;
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
#warning Add error handling if not able to send the token
    }];
    
}

- (void)application:(UIApplication*)application didFailToRegisterForRemoteNotificationsWithError:(NSError*)error {

    
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"TextSecure needs push notifications" message:@"We couldn't enable push notifications. TexSecure uses them heavily. Please try registering again." delegate:self cancelButtonTitle:@"Ok" otherButtonTitles:nil, nil];
    [alert show];
    
#ifdef DEBUG
#warning registering with dummy ID so that we can proceed in the simulator. You'll want to change this!
  [self application:application didRegisterForRemoteNotificationsWithDeviceToken:[[NSData alloc] initWithBase64Encoding:[@"christine" base64Encoded]]];
#endif
  
}


- (void)application:(UIApplication *)application didReceiveRemoteNotification:(NSDictionary *)userInfo {
	// TODO: add new message here!
	[self handlePush:userInfo];
}

-(void) handlePush:(NSDictionary *)pushInfo {
#warning unencrypted pipline
	NSLog(@"full message json %@",pushInfo);
  NSData *payload = [NSData dataFromBase64String:[pushInfo objectForKey:@"m"]];
  unsigned char version[1];
  unsigned char iv[16];
  int ciphertext_length=([payload length]-10-17)*sizeof(char);
  unsigned char *ciphertext =  (unsigned char*)malloc(ciphertext_length);
  unsigned char mac[10];
  [payload getBytes:version range:NSMakeRange(0, 1)];
  [payload getBytes:iv range:NSMakeRange(1, 16)];
  [payload getBytes:ciphertext range:NSMakeRange(17, [payload length]-10-17)];
  [payload getBytes:mac range:NSMakeRange([payload length]-10, 10)];


  NSData* signalingKey = [NSData dataFromBase64String:[Cryptography getSignalingKeyToken]];
  NSLog(@"signaling key %@",[Cryptography getSignalingKeyToken]);
  // Actually only the first 32 bits of this are the crypto key
  NSData* signalingKeyAESKeyMaterial = [signalingKey subdataWithRange:NSMakeRange(0, 32)];
  NSData* signalingKeyHMACKeyMaterial = [signalingKey subdataWithRange:NSMakeRange(32, 20)];
  NSData* decryption=[Cryptography CC_AES256_CBC_Decryption:[NSData dataWithBytes:ciphertext length:ciphertext_length] withKey:signalingKeyAESKeyMaterial withIV:[NSData dataWithBytes:iv length:16] withVersion:[NSData dataWithBytes:version length:1] withMacKey:signalingKeyHMACKeyMaterial forMac:[NSData dataWithBytes:mac length:10]];
  
  // Now get the protocol buffer message out
  textsecure::IncomingPushMessageSignal *fullMessageInfoRecieved = [IncomingPushMessageSignal getIncomingPushMessageSignalForData:decryption];
  
  NSString *decryptedMessage = [IncomingPushMessageSignal getMessageBody:fullMessageInfoRecieved];
  NSString *decryptedMessageAndInfo = [IncomingPushMessageSignal prettyPrint:fullMessageInfoRecieved];
  UIAlertView *pushAlert = [[UIAlertView alloc] initWithTitle:@"decrypted message" message:decryptedMessageAndInfo delegate:self cancelButtonTitle:nil otherButtonTitles:@"OK", nil];
  [pushAlert show];
#warning we need to handle this push!, the UI will need to select the appropriate message view

  [[TSMessagesManager sharedManager] processPushNotification:pushInfo];
}

#pragma mark - HockeyApp Delegate Methods

#ifdef DEBUG
- (NSString *)customDeviceIdentifierForUpdateManager:(BITUpdateManager *)updateManager {
#ifndef CONFIGURATION_AppStore
	if ([[UIDevice currentDevice] respondsToSelector:@selector(uniqueIdentifier)])
		return [[UIDevice currentDevice] performSelector:@selector(uniqueIdentifier)];
#endif
	return nil;
}
#endif

@end
