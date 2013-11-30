//
//  IncomingPushMessageSignal.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 10/24/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "IncomingPushMessageSignal.hh"


@implementation IncomingPushMessageSignal



-(id) init {
  // Testing things out
#warning remove this type of init
  if(self = [super init]) {
    // Creating message
    /*
     Type
     Allowed source
     Destinations
     Timestamp
     Allocated Message
     */
    std::string phoneNumber ="+41000000000";
    std::string message = "Hey, what's up. I'm using TextSecure.";
    textsecure::IncomingPushMessageSignal *incomingPushMessage = new textsecure::IncomingPushMessageSignal();
    incomingPushMessage->set_type(0); // 0=plaintext,1=ciphertext,3=prekeybundle
    incomingPushMessage->set_allocated_source(&phoneNumber);
    //incomingPushMessage->set_destinations(<#int index#>, <#const ::std::string &value#>); //leaving empty, not a group message.
    incomingPushMessage->set_timestamp((uint64_t)[[NSDate date] timeIntervalSince1970]);
    incomingPushMessage->set_allocated_message(&message);
    // Printing message
    [IncomingPushMessageSignal prettyPrint:incomingPushMessage];
    // Serializing message
    NSData* serializedIncomingPushMessage = [IncomingPushMessageSignal getDataForIncomingPushMessageSignal:incomingPushMessage];
    
    // Deserializing message
    textsecure::IncomingPushMessageSignal *deserializedIncomingPushMessage = [IncomingPushMessageSignal getIncomingPushMessageSignalForData:serializedIncomingPushMessage];
    // Printing deserialized message
    [IncomingPushMessageSignal prettyPrint:deserializedIncomingPushMessage];
    
    
    
  }
  return self;
}

// Serialize IncomingPushMessageSignal to NSData.
+ (NSData *)getDataForIncomingPushMessageSignal:(textsecure::IncomingPushMessageSignal *)incomingPushMessage {
  std::string ps = incomingPushMessage->SerializeAsString();
  return [NSData dataWithBytes:ps.c_str() length:ps.size()];
}

// De-serialize IncomingPushMessageSignal from an NSData object.
+ (textsecure::IncomingPushMessageSignal *)getIncomingPushMessageSignalForData:(NSData *)data {
  int len = [data length];
  char raw[len];
  textsecure::IncomingPushMessageSignal *incomingPushMessage = new textsecure::IncomingPushMessageSignal;
  [data getBytes:raw length:len];
  incomingPushMessage->ParseFromArray(raw, len);
  return incomingPushMessage;
}

// Serialize PushMessageContent to NSData.
+ (NSData *)getDataForPushMessageContent:(textsecure::PushMessageContent *)pushMessageContent {
  std::string ps = pushMessageContent->SerializeAsString();
  return [NSData dataWithBytes:ps.c_str() length:ps.size()];
}


// De-serialize PushMessageContent from an NSData object.
+ (textsecure::PushMessageContent *)getPushMessageContentForData:(NSData *)data {
  int len = [data length];
  char raw[len];
  textsecure::PushMessageContent *pushMessageContent = new textsecure::PushMessageContent;
  [data getBytes:raw length:len];
  pushMessageContent->ParseFromArray(raw, len);
  return pushMessageContent;
}

// Create PushMessageContent from it's Objective C contents
+ (NSData *)createSerializedPushMessageContent:(NSString*) message withAttachments:(NSArray*) attachments {
#warning no attachments suppoart yet
  textsecure::PushMessageContent *pushMessageContent = new textsecure::PushMessageContent();
  const std::string body([message cStringUsingEncoding:NSASCIIStringEncoding]);
  pushMessageContent->set_body(body);
  NSData *serializedPushMessageContent = [IncomingPushMessageSignal getDataForPushMessageContent:pushMessageContent];
  delete pushMessageContent;
  return serializedPushMessageContent;
}

+ (void)prettyPrint:(textsecure::IncomingPushMessageSignal *)incomingPushMessageSignal {
  /*
   Type
   Allowed source
   Destinations
   Timestamp
   Allocated Message
   */
  
  const uint32_t cppType = incomingPushMessageSignal->type();
  const std::string cppSource = incomingPushMessageSignal->source();
  const uint64_t cppTimestamp = incomingPushMessageSignal->timestamp();
  const std::string cppMessage = incomingPushMessageSignal->message();
  /* testing conversion to objective c objects */
  NSNumber* type = [NSNumber numberWithInteger:cppType];
  NSString* source = [NSString stringWithCString:cppSource.c_str() encoding:NSASCIIStringEncoding];
  NSNumber* timestamp = [NSNumber numberWithInteger:cppTimestamp];
  NSString* messsage = [NSString stringWithCString:cppMessage.c_str() encoding:NSASCIIStringEncoding];
  
  NSLog([NSString stringWithFormat:@"Type: %@ \n source: %@ \n timestamp: %@, message: %@",
         type,source,timestamp,messsage]);
}
// Dlog
+ (void)prettyPrintPushMessageContent:(textsecure::PushMessageContent *)pushMessageContent {
  const std::string cppBody = pushMessageContent->body();
  NSString* body = [NSString stringWithCString:cppBody.c_str() encoding:NSASCIIStringEncoding];
  NSLog(@"recieved message %@",body);
#warning doesn't handle attachments yet

}

@end
