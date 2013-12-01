//
//  CryptographyDatabase.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 10/12/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "EncryptedDatabase.h"
#import "Cryptography.h"
#import "FMDatabase.h"
#import "FMDatabaseQueue.h"
#import "ECKeyPair.h"
#import "FilePath.h"
#import "TSMessage.h"
#import "TSThread.h"
#import "TSContact.h"

#define kKeyForInitBool @"DBWasInit"

static EncryptedDatabase *SharedCryptographyDatabase = nil;


@implementation EncryptedDatabase
-(id) init {
    @throw [NSException exceptionWithName:@"incorrect initialization" reason:@"must be initialized with password" userInfo:nil];
    
}

-(void)storeTSThread:(TSThread*)thread{
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        for(TSContact* contact in thread.participants) {
            [contact save];
        }
    }];
}

-(void)findTSContactForPhoneNumber:(NSString*)phoneNumber{
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchIfExitInDB = [db executeQuery:@"SELECT registeredID FROM contacts WHERE registered_phone_number = :phoneNumber " withParameterDictionary:@{@"phoneNumber":phoneNumber}];
        
        if ([searchIfExitInDB next]) {
            // That was found :)
            NSLog(@"Entry %@", [searchIfExitInDB stringForColumn:@"useraddressbookid"]);
        }
        
        [searchIfExitInDB close];
    }];
}

-(void)storeTSContact:(TSContact*)contact{
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchIfExitInDB = [db executeQuery:@"SELECT registeredID FROM contacts WHERE registered_phone_number = :phoneNumber " withParameterDictionary:@{@"phoneNumber":contact.registeredID}];
        
        if ([searchIfExitInDB next]) {
            // the phone number was found, let's now update the contact
            [db executeUpdate:@"UPDATE contacts SET relay = :relay, useraddressbookid :userABID, identitykey = :identityKey, identityverified = :identityKeyIsVerified, supports_sms = :supportsSMS, next_key = :nextKey WHERE registered_phone_number = :registeredID" withParameterDictionary:@{@"registeredID": contact.registeredID, @"relay": contact.relay, @"userABID": contact.userABID, @"identityKey": contact.identityKey, @"identityKeyIsVerified":[NSNumber numberWithInt:((contact.identityKeyIsVerified)?1:0)], @"supportsSMS":[NSNumber numberWithInt:((contact.supportsSMS)?1:0)], @"nextKey":contact.nextKey}];
        }
        else{
            // the contact doesn't exist, let's create him
            [db executeUpdate:@"REPLACE INTO contacts (:registeredID,:relay , :userABID, :identityKey, :identityKeyIsVerified, :supportsSMS, :nextKey)" withParameterDictionary:@{@"registeredID": contact.registeredID, @"relay": contact.relay, @"userABID": contact.userABID, @"identityKey": contact.identityKey, @"identityKeyIsVerified":[NSNumber numberWithInt:((contact.identityKeyIsVerified)?1:0)], @"supportsSMS":[NSNumber numberWithInt:((contact.supportsSMS)?1:0)], @"nextKey":contact.nextKey}];
        }
    }];
}

+(void) setupDatabaseWithPassword:(NSString*) userPassword {
    if (!SharedCryptographyDatabase) {
        //first call of this during the app lifecyle
        SharedCryptographyDatabase = [[EncryptedDatabase alloc] initWithPassword:userPassword];
    }
    // We also want to generate the identity keys if they haven't been
    if(![SharedCryptographyDatabase getIdentityKey]) {
        [Cryptography generateAndStoreIdentityKey];
        [Cryptography generateAndStoreNewPreKeys:70];
    }
}


+(id) database {
    if (!SharedCryptographyDatabase) {
        @throw [NSException exceptionWithName:@"incorrect initialization" reason:@"database must be accessed with password prior to being able to use this method" userInfo:nil];
    }
    return SharedCryptographyDatabase;
    
}



-(id) initWithPassword:(NSString*) userPassword {
    if(self=[super init]) {
        self.dbQueue = [FMDatabaseQueue databaseQueueWithPath:[FilePath pathInDocumentsDirectory:@"cryptography.db"]];
        [self.dbQueue inDatabase:^(FMDatabase *db) {
            NSData * key = [Cryptography getMasterSecretKey:userPassword];
            if(key!=nil) {
                BOOL success = [db setKeyWithData:key];
                if(!success) {
                    @throw [NSException exceptionWithName:@"unable to encrypt" reason:@"this shouldn't happen" userInfo:nil];
                }
                [db executeUpdate:@"CREATE TABLE IF NOT EXISTS persistent_settings (setting_name TEXT UNIQUE,setting_value TEXT)"];
                [db executeUpdate:@"CREATE TABLE IF NOT EXISTS personal_prekeys (prekey_id INTEGER UNIQUE,public_key TEXT,private_key TEXT, last_counter INTEGER)"];
#warning we will want a subtler format than this, prototype message db format
                [db executeUpdate:@"CREATE TABLE IF NOT EXISTS messages (thread_id INTEGER,message TEXT,sender_id TEXT,recipient_id TEXT, timestamp DATE)"];
                [db executeUpdate:@"CREATE TABLE IF NOT EXISTS contacts (registered_phone_number TEXT,relay TEXT, useraddressbookid INTEGER, identitykey TEXT, identityverified INTEGER, supports_sms INTEGER, next_key TEXT)"];
                [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:kKeyForInitBool];
                [[NSUserDefaults standardUserDefaults] synchronize];
            }
        }];
    }
    return self;
    
}

-(void) storeMessage:(TSMessage*)message {
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        
        NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat: @"yyyy-MM-dd HH:mm:ss"];
        [dateFormatter setTimeZone:[NSTimeZone localTimeZone]];
        NSString *sqlDate = [dateFormatter stringFromDate:message.messageTimestamp];
#warning every message is on the same thread! also we only support one recipient
        [db executeUpdate:@"INSERT OR REPLACE INTO messages (thread_id,message,sender_id,recipient_id,timestamp) VALUES (?, ?, ?, ?, ?)",[NSNumber numberWithInt:0],message.message,message.senderId,message.recipientId,sqlDate];
    }];
}

-(NSArray*) getMessagesOnThread:(int) threadId {
    NSMutableArray *messageArray = [[NSMutableArray alloc] init];
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        //    FMResultSet  *rs = [db executeQuery:[NSString stringWithFormat:@"SELECT * FROM messages WHERE thread_id=%d ORDER BY timestamp",threadId]];
        FMResultSet  *rs = [db executeQuery:@"select * from messages"];
        while([rs next]) {
            NSString* timestamp = [rs stringForColumn:@"timestamp"];
            NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
            [dateFormatter setDateFormat: @"yyyy-MM-dd HH:mm:ss"];
            [dateFormatter setTimeZone:[NSTimeZone localTimeZone]];
            NSDate *date = [dateFormatter dateFromString:timestamp];
            [messageArray addObject:[[TSMessage alloc] initWithMessage:[rs stringForColumn:@"message"] sender:[rs stringForColumn:@"sender_id"] recipients:[[NSArray alloc] initWithObjects:[rs stringForColumn:@"recipient_id"],nil] sentOnDate:date]];
            
        }
    }];
    return messageArray;
    
}

+(BOOL) dataBaseWasInitialized{
    return [[NSUserDefaults standardUserDefaults] boolForKey:kKeyForInitBool];
}

-(void) savePersonalPrekeys:(NSArray*)prekeyArray {
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        for(ECKeyPair* keyPair in prekeyArray) {
            [db executeUpdate:@"INSERT OR REPLACE INTO personal_prekeys (prekey_id,public_key,private_key,last_counter) VALUES (?,?,?,?)",[NSNumber numberWithInt:[keyPair prekeyId]],[keyPair publicKey],[keyPair privateKey],[NSNumber numberWithInt:0]];
        }
    }];
}

-(NSArray*) getPersonalPrekeys {
    NSMutableArray *prekeyArray = [[NSMutableArray alloc] init];
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        FMResultSet  *rs = [db executeQuery:[NSString stringWithFormat:@"SELECT * FROM personal_prekeys"]];
        while([rs next]) {
            ECKeyPair *keyPair = [[ECKeyPair alloc] initWithPublicKey:[rs stringForColumn:@"public_key"]
                                                           privateKey:[rs stringForColumn:@"private_key"]
                                                             prekeyId:[rs intForColumn:@"prekey_id"]];
            [prekeyArray addObject:keyPair];
        }
    }];
    return prekeyArray;
}


-(int) getLastPrekeyId {
    __block int counter = -1;
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        FMResultSet  *rs = [db executeQuery:[NSString stringWithFormat:@"SELECT prekey_id FROM personal_prekeys WHERE last_counter=\"1\""]];
        if([rs next]){
            counter = [rs intForColumn:@"prekey_id"];
        }
        [rs close];
        
    }];
    return counter;
    
}

-(void) setLastPrekeyId:(int)lastPrekeyId {
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        [db executeUpdate:@"UPDATE personal_prekeys SET last_counter=0"];
        [db executeUpdate:[NSString stringWithFormat:@"UPDATE personal_prekeys SET last_counter=1 WHERE prekey_id=%d",lastPrekeyId]];
    }];
}


-(void) storeIdentityKey:(ECKeyPair*) identityKey {
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        [db executeUpdate:@"INSERT OR REPLACE INTO persistent_settings (setting_name,setting_value) VALUES (?, ?)",@"identity_key_private",[identityKey privateKey]];
        [db executeUpdate:@"INSERT OR REPLACE INTO persistent_settings (setting_name,setting_value) VALUES (?, ?)",@"identity_key_public",[identityKey publicKey]];
    }];
    
}


-(ECKeyPair*) getIdentityKey {
    __block NSString* identityKeyPrivate = nil;
    __block NSString* identityKeyPublic = nil;
    [self.dbQueue inDatabase:^(FMDatabase *db) {
        FMResultSet  *rs = [db executeQuery:[NSString stringWithFormat:@"SELECT setting_value FROM persistent_settings WHERE setting_name=\"identity_key_public\""]];
        if([rs next]){
            identityKeyPublic = [rs stringForColumn:@"setting_value"];
        }
        [rs close];
        rs = [db executeQuery:[NSString stringWithFormat:@"SELECT setting_value FROM persistent_settings WHERE setting_name=\"identity_key_private\""]];
        
        if([rs next]){
            identityKeyPrivate = [rs stringForColumn:@"setting_value"];
        }
        [rs close];
    }];
    if(identityKeyPrivate==nil || identityKeyPublic==nil) {
        return nil;
    }
    else {
        return [[ECKeyPair alloc] initWithPublicKey:identityKeyPublic privateKey:identityKeyPrivate];
    }
}

@end
