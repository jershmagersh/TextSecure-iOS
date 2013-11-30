//
//  TSGetRecipientPrekey.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 11/30/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSRecipientPrekeyRequest.h"
#import "TSContact.h"
@implementation TSRecipientPrekeyRequest

/*
 usage:
 #warning we don't need to do this every time, just at the beginning of a session... this should all in the end be handled by something that has a concept of sessions
 [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSRecipientPrekeyRequest alloc] initWithRecipient:self.contact] success:^(AFHTTPRequestOperation *operation, id responseObject) {
 
 switch (operation.response.statusCode) {
 case 200:
 DLog(@"we have prekey of contact %@",responseObject);
 // So let's encrypt a message using this
 
 
 break;
 
 default:
 DLog(@"Issue getting contacts' prekeys");
 #warning Add error handling if not able to get contacts prekey
 break;
 }
 } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
 #warning Add error handling if not able to send the token
 DLog(@"failure %d, %@",operation.response.statusCode,operation.response.description);
 
 
 }];
*/
-(TSRequest*) initWithRecipient:(TSContact*) contact {
  NSString* recipientInformation;
  if([contact.relay length]){
    recipientInformation = [NSString stringWithFormat:@"%@?%@",contact.registeredId,contact.relay];
  }
  else {
    recipientInformation=contact.registeredId;
  }
  self = [super initWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@/%@", textSecureKeysAPI, recipientInformation]]];
    
  [self setHTTPMethod:@"GET"];
  
  return self;
}

@end
