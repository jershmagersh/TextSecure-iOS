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
#import "EncryptedDatabase.h"
#import "TSRegisterForPushRequest.h"
#import "NSString+Conversion.h"
#warning remove the below imports
#import "IncomingPushMessageSignal.hh"
#import "TSContact.h"
#import "NSData+Base64.h"
#import "TSSubmitMessageRequest.h"
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
	if([UserDefaults hasVerifiedPhoneNumber] && [EncryptedDatabase dataBaseWasInitialized]) {
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
#warning we will want better error handling, including reprompting if user enters password wrong
  if(buttonIndex==1) {
    NSString* password = [[alertView textFieldAtIndex:0] text];
    [EncryptedDatabase setupDatabaseWithPassword:password];
    // TODO: remove
    [Cryptography generateAndStoreNewPreKeys:70];

    
  }
}

-(void) sendMessage:(NSNotification*)notification {
  TSContact* contact = [[notification userInfo] objectForKey:@"contact"];
  NSString *message = [[notification userInfo] objectForKey:@"message"];
  NSString *serializedMessage = [[IncomingPushMessageSignal createSerializedPushMessageContent:message withAttachments:nil] base64Encoding];
  //Tests deserialization [IncomingPushMessageSignal prettyPrintPushMessageContent:[IncomingPushMessageSignal getPushMessageContentForData:[NSData dataFromBase64String:serializedMessage]]];
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
    DLog(@"failure %d, %@",operation.response.statusCode,operation.response.description);
    
    
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
	
	NSLog(@"full message json %@",pushInfo);
  UIAlertView *pushAlert = [[UIAlertView alloc] initWithTitle:[pushInfo objectForKey:@"alert"] message:[pushInfo objectForKey:@"m"] delegate:self cancelButtonTitle:nil otherButtonTitles:@"OK", nil];
  [pushAlert show];
#warning we need to handle this push!, the UI will need to select the appropriate message view

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
