//
//  TSSubmitMessageRequest.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 11/30/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSSubmitMessageRequest.h"
#import "TSContact.h"
@implementation TSSubmitMessageRequest

-(TSRequest*) initWithRecipient:(TSContact*) contact message:(NSString*) messageBody {
#warning 0 indicates unencrypted should change to be encrypted
  NSMutableDictionary *messageDictionary = [[NSMutableDictionary alloc]
                                            initWithObjects:[[NSArray alloc]
                                                             initWithObjects:[NSNumber numberWithInt:0],
                                                             [contact registeredId],
                                                             messageBody,
                                                             [NSNumber numberWithFloat:[[NSDate date] timeIntervalSince1970]],nil]
                                            forKeys:[[NSArray alloc] initWithObjects:@"type",@"destination",@"body",@"timestamp", nil]];
  if ([contact.relay length]>0) {
    [messageDictionary setObject:@"relay" forKey:contact.relay];
  }
  self = [super initWithURL:[NSURL URLWithString:textSecureMessagesAPI]];
  NSMutableDictionary *allMessages = [[NSMutableDictionary alloc] initWithObjectsAndKeys:[[NSArray alloc] initWithObjects: messageDictionary,nil],@"messages", nil];
  [self setHTTPMethod:@"PUT"];
  [self setParameters:allMessages];
  return self;
}

@end
