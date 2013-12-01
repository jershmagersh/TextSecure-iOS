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
#warning adding relay-what should I set this to? as it looks like it may not be optional
  long fakeTime = 10000000;
  NSMutableDictionary *messageDictionary = [[NSMutableDictionary alloc]
                                            initWithObjects:[[NSArray alloc]
                                                             initWithObjects:[NSNumber numberWithInt:0],
                                                             [contact registeredId],
                                                             messageBody,
                                                             [NSNumber numberWithLong:fakeTime],
                                                             nil]
                                            forKeys:[[NSArray alloc] initWithObjects:@"type",@"destination",@"body",@"timestamp" ,nil]];

  // Moxies messages
  messageDictionary = [[NSMutableDictionary alloc]
                                            initWithObjects:[[NSArray alloc]
                                                             initWithObjects:[NSNumber numberWithInt:3],
                                                             @"+41795994505",
                                                             @"Igijh9QEEiEFnOoLwvn2gM6F1KFB9mb6VereQj2yza4FKKgc2cGn820aIQW4uJUw/HJTj4CZf/7JJBeL9ZPSUzxIqxDSm+KmVFwFeiJFIgohBd6xcuFRwYyqCA7PwPvtwq52dz+VqRSTdfQtYdpcGoAZEAAYACITVgrobdugC+NH+vNGYfMdR225dq2a+KETkpoq",
                                                             nil]
                                            forKeys:[[NSArray alloc] initWithObjects:@"type",@"destination",@"body",nil]];
//  if ([contact.relay length]>0) {
//    [messageDictionary setObject:contact.relay forKey:@"relay"];
//  }
//  else {
//#warning should change this to whatever default should be or leave empty as Moxie specifies
//    [messageDictionary setObject:textSecureServer forKey:@"relay"];
//    
//  }

  self = [super initWithURL:[NSURL URLWithString:textSecureMessagesAPI]];
  NSMutableDictionary *allMessages = [[NSMutableDictionary alloc] initWithObjectsAndKeys:[[NSArray alloc] initWithObjects: messageDictionary,nil],@"messages", nil];
  NSLog(@"sending to server %@",allMessages);
  [self setHTTPMethod:@"POST"];
  [self setParameters:allMessages];
  return self;
}

@end
