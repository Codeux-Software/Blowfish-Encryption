/* *********************************************************************
 *
 *        Copyright (c) 2015 - 2018 Codeux Software, LLC
 *     Please see ACKNOWLEDGEMENT for additional information.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of "Codeux Software, LLC", nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *********************************************************************** */

/*
 * OTRKit.m
 * OTRKit
 *
 * Created by Chris Ballinger on 9/4/11.
 * Copyright (c) 2012 Chris Ballinger. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the project's author nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

NS_ASSUME_NONNULL_BEGIN

@class OTRKit;
@class OTRKitConcreteObject;

@class OTRTLV;

typedef NS_ENUM(NSUInteger, OTRKitMessageState) {
	OTRKitMessageStatePlaintext,
	OTRKitMessageStateEncrypted,
	OTRKitMessageStateFinished
};

typedef NS_ENUM(NSUInteger, OTRKitPolicy) {
	OTRKitPolicyDefault				= 0,
	OTRKitPolicyNever,
	OTRKitPolicyOpportunistic,
	OTRKitPolicyManual,
	OTRKitPolicyAlways,
};

typedef NS_ENUM(NSUInteger, OTRKitOfferState) {
	OTRKitOfferStateNone,
	OTRKitOfferStateSent,
	OTRKitOfferStateRejected,
	OTRKitOfferStateAccepted
};

typedef NS_ENUM(NSUInteger, OTRKitSMPEvent) {
	OTRKitSMPEventNone,
	OTRKitSMPEventAskForSecret,
	OTRKitSMPEventAskForAnswer,
	OTRKitSMPEventCheated,
	OTRKitSMPEventInProgress,
	OTRKitSMPEventSuccess,
	OTRKitSMPEventFailure,
	OTRKitSMPEventAbort,
	OTRKitSMPEventError
};

typedef NS_ENUM(NSUInteger, OTRKitMessageEvent) {
	OTRKitMessageEventNone,
	OTRKitMessageEventEncryptionRequired,
	OTRKitMessageEventEncryptionError,
	OTRKitMessageEventConnectionEnded,
	OTRKitMessageEventSetupError,
	OTRKitMessageEventMessageReflected,
	OTRKitMessageEventMessageResent,
	OTRKitMessageEventReceivedMessageNotInPrivate,
	OTRKitMessageEventReceivedMessageUnreadable,
	OTRKitMessageEventReceivedMessageMalformed,
	OTRKitMessageEventLogHeartbeatReceived,
	OTRKitMessageEventLogHeartbeatSent,
	OTRKitMessageEventReceivedMessageGeneralError,
	OTRKitMessageEventReceivedMessageUnencrypted,
	OTRKitMessageEventReceivedMessageUnrecognized,
	OTRKitMessageEventReceivedMessageForOtherInstance
};

typedef NS_ENUM(NSUInteger, OTRKitMessageType) {
	OTRKitMessageTypeNotOTR,
	OTRKitMessageTypeTaggedPlainText,
	OTRKitMessageTypeQuery,
	OTRKitMessageTypeDHCommit,
	OTRKitMessageTypeDHKey,
	OTRKitMessageTypeRevealSignature,
	OTRKitMessageTypeSignature,
	OTRKitMessageTypeV1KeyExchange,
	OTRKitMessageTypeData,
	OTRKitMessageTypeError,
	OTRKitMessageTypeUnknown
};

/** 
 *  Notification fired when a fingerprint and/or its attributes change. This 
 *  includes a new fingerprint arriving, one being deleted, or the trust of an 
 *  existing fingerprint being modified.
 * 
 *  This notification does not contain a userInfo dictionary.
 */
extern NSString * const OTRKitListOfFingerprintsDidChangeNotification;

/**
 *  Notification fired when the message state of any conversation has changed.
 *
 *  This notification does not contain a userInfo dictionary.
 */
extern NSString * const OTRKitMessageStateDidChangeNotification;

@protocol OTRKitDelegate <NSObject>
@required

/**
 *  This method **MUST** be implemented or OTR will not work. All outgoing messages
 *  should be sent first through OTRKit encodeMessage and then passed from this delegate
 *  to the appropriate chat protocol manager to send the actual message.
 *
 *  @param otrKit		Reference to shared instance
 *  @param message		Message to be sent over the network. May contain cipher text.
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 *  @param tag			Optional tag to attached to message. Only used locally.
 */
- (void) otrKit:(OTRKit *)otrKit
  injectMessage:(NSString *)message
	   username:(NSString *)username
	accountName:(NSString *)accountName
	   protocol:(NSString *)protocol
			tag:(nullable id)tag;

/**
 *  All outgoing messages should be sent to the OTRKit encodeMessage method before being
 *  sent over the network.
 *
 *  @param otrKit			Reference to shared instance
 *  @param encodedMessage   Plain text message
 *  @param wasEncrypted		Whether or not encodedMessage message is cipher text, or just plaintext appended with the opportunistic whitespace. This is just a check of the encodedMessage message for a "?OTR" prefix.
 *  @param username			The account name of the remote user
 *  @param accountName		The account name of the local user
 *  @param protocol			The protocol of the exchange
 *  @param tag				Optional tag to attached to message. Only used locally.
 *  @param error			Error describing why encodedMessage is nil
 */
- (void) otrKit:(OTRKit *)otrKit
 encodedMessage:(nullable NSString *)encodedMessage
   wasEncrypted:(BOOL)wasEncrypted
	   username:(NSString *)username
	accountName:(NSString *)accountName
	   protocol:(NSString *)protocol
			tag:(nullable id)tag
		  error:(nullable NSError *)error;

/**
 *  All incoming messages should be sent to the OTRKit decodeMessage method before being
 *  processed by your application. You should only display the messages coming from this delegate method.
 *
 *  @param otrKit			Reference to shared instance
 *  @param decodedMessage	Plain text message to display to the user. May be nil if other party is sending raw TLVs without messages attached.
 *  @param wasEncrypted		Whether or not the original message sent to decodeMessage: was encrypted or plain text. This is just a check of the original message for a "?OTR" prefix.
 *  @param tlvs				OTRTLV values that may be present.
 *  @param username			The account name of the remote user
 *  @param accountName		The account name of the local user
 *  @param protocol			The protocol of the exchange
 *  @param tag				Optional tag to attached to message. Only used locally.
 */
- (void) otrKit:(OTRKit *)otrKit
 decodedMessage:(nullable NSString *)decodedMessage
   wasEncrypted:(BOOL)wasEncrypted
		   tlvs:(NSArray<OTRTLV *> *)tlvs
	   username:(NSString *)username
	accountName:(NSString *)accountName
	   protocol:(NSString *)protocol
			tag:(nullable id)tag;

/**
 *  When the encryption status changes this method is called
 *
 *  @param otrKit		Reference to shared instance
 *  @param messageState Plain text, encrypted or finished
 *  @param username     The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 */
- (void)    otrKit:(OTRKit *)otrKit
updateMessageState:(OTRKitMessageState)messageState
		  username:(NSString *)username
	   accountName:(NSString *)accountName
		  protocol:(NSString *)protocol;

/**
 *  libotr likes to know if users are still "online". This method
 *  is called synchronously on the callback queue so be careful.
 *
 *  @param otrKit		Reference to shared instance
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 *
 *  @return online status of username
 */
- (BOOL)       otrKit:(OTRKit *)otrKit
   isUsernameLoggedIn:(NSString *)username
		  accountName:(NSString *)accountName
			 protocol:(NSString *)protocol;

/**
 *  Show a dialog so the user can confirm when a user's fingerprint changes.
 *
 *  @param otrKit      Reference to shared instance
 *  @param theirHash   Remote user's fingerprint
 *  @param ourHash     Local user's fingerprint
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (void)                           otrKit:(OTRKit *)otrKit
  showFingerprintConfirmationForTheirHash:(NSString *)theirHash
								  ourHash:(NSString *)ourHash
								 username:(NSString *)username
							  accountName:(NSString *)accountName
								 protocol:(NSString *)protocol;

/**
 *  Method invoked when the trust state of the active fingerprint for a user changes.
 *
 *  @param otrKit      Reference to shared instance
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 *  @param verified    Whether or not to trust this fingerprint
 */
- (void)							  otrKit:(OTRKit *)otrKit
fingerprintIsVerifiedStateChangedForUsername:(NSString *)username
								 accountName:(NSString *)accountName
			   						protocol:(NSString *)protocol
									verified:(BOOL)verified;

/**
 *  Implement this if you plan to handle Socialist Millionaire Problem (SMP) calls.
 *
 *  @param otrKit		Reference to shared instance
 *  @param event		The type of event
 *  @param progress		Percent progress of the negotiation
 *  @param question		Question that should be displayed to user
 *  @param username     The account name of the remote user
 *  @param accountName  The account name of the local user
 *  @param protocol     The protocol of the exchange
 *  @param error		Error describing the problem
 */
- (void) otrKit:(OTRKit *)otrKit
 handleSMPEvent:(OTRKitSMPEvent)event
	   progress:(double)progress
	   question:(nullable NSString *)question
	   username:(NSString *)username
	accountName:(NSString *)accountName
	   protocol:(NSString *)protocol
		  error:(nullable NSError *)error;

/**
 *  Implement this delegate method to handle message events.
 *
 *  @param otrKit		Reference to shared instance
 *  @param event		Message event
 *  @param message		Offending message
 *  @param username     The account name of the remote user
 *  @param accountName  The account name of the local user
 *  @param protocol     The protocol of the exchange
 *  @param tag			Tag to attach additional application-specific data to message. Only used locally.
 *  @param error		Error describing the problem
 */
- (void)    otrKit:(OTRKit *)otrKit
handleMessageEvent:(OTRKitMessageEvent)event
		   message:(NSString *)message
		  username:(NSString *)username
	   accountName:(NSString *)accountName
		  protocol:(NSString *)protocol
			   tag:(nullable id)tag
			 error:(nullable NSError *)error;

/**
 *  When a remote user requests a shared symmetric key, this will be called.
 *
 *  @param otrKit			Reference to shared instance
 *  @param symmetricKey		Key data
 *  @param use				Integer tag for identifying the use for the key
 *  @param useData			Any extra data to attach
 *  @param username         The account name of the remote user
 *  @param accountName      The account name of the local user
 *  @param protocol         The protocol of the exchange
 */
- (void)        otrKit:(OTRKit *)otrKit
  receivedSymmetricKey:(NSData *)symmetricKey
				forUse:(NSUInteger)use
			   useData:(NSData *)useData
			  username:(NSString *)username
		   accountName:(NSString *)accountName
			  protocol:(NSString *)protocol;

@optional

/**
 *  Called when starting to generate a private key, may take a while.
 *
 *  @param otrKit      Reference to shared instance
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (void)                             otrKit:(OTRKit *)otrKit
willStartGeneratingPrivateKeyForAccountName:(NSString *)accountName
								   protocol:(NSString *)protocol;

/**
 *  Called when key generation has finished, canceled, or there was an error.
 *
 *  @param otrKit      Reference to shared instance
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 *  @param error       Any error that may have occurred
 */
- (void)                             otrKit:(OTRKit *)otrKit
didFinishGeneratingPrivateKeyForAccountName:(NSString *)accountName
								   protocol:(NSString *)protocol
									  error:(nullable NSError *)error;

/**
 *  Conditionally ignore an incoming message (message to decode)
 *
 *  @param otrKit		Reference to shared instance
 *  @param message		The message to be decoded
 *  @param messageType	The type of message
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 *
 * @return YES to ignore message
 */
- (BOOL)   otrKit:(OTRKit *)otrKit
	ignoreMessage:(NSString *)message
	  messageType:(OTRKitMessageType)messageType
		 username:(NSString *)username
	  accountName:(NSString *)accountName
		 protocol:(NSString *)protocol;
@end

@interface OTRKit : NSObject
@property (nonatomic, weak, nullable) id<OTRKitDelegate> delegate;

/**
 *  Defaults to main queue. All delegate and block callbacks will be done on this queue.
 */
@property (nonatomic, strong, nullable) dispatch_queue_t delegateQueue;

/**
 * By default uses `OTRKitPolicyDefault`
 */
@property (nonatomic) OTRKitPolicy otrPolicy;

/**
 *  Path to where the OTR private keys and related data is stored.
 */
@property (nonatomic, copy, readonly) NSString *dataPath;

/**
 *  Path to the OTR private keys file.
 */
@property (nonatomic, copy, readonly) NSString *privateKeyPath;

/**
 *  Path to the OTR fingerprints file.
 */
@property (nonatomic, copy, readonly) NSString *fingerprintsPath;

/**
 *  Path to the OTRv3 Instance tags file.
 */
@property (nonatomic, copy, readonly) NSString *instanceTagsPath;

/**
 *  The symbol that is used for separating user information. For example, 
 *  an account name can be supplied as user@example.com whereas @ is the 
 *  separator character. This is used during authentication to provide a 
 *  user friendly way of viewing account name information. Default value
 *  for property is at sign - do not set to empty.
 */
@property (nonatomic, copy) NSString *accountNameSeparator;

/**
 *  Always use the sharedInstance. Using two OTRKits within your application
 *  may exhibit strange problems.
 *
 *  @return singleton instance
 */
+ (instancetype)sharedInstance;

/**
 * You must call this method before any others.
 *
 * @param dataPath This is a path to a folder where private keys, fingerprints, and instance tags will be stored. If this is nil a default path will be chosen for you.
 */
- (void)setupWithDataPath:(nullable NSString *)dataPath;

/**
 *  For specifying fragmentation for a protocol.
 *
 *  @param maxSize		Max size of protocol messages in bytes
 *  @param protocol		The protocol of the exchange
 */
- (void)setMaximumProtocolSize:(int)maxSize forProtocol:(NSString *)protocol;

/**
 * Encodes a message and optional array of OTRTLVs, splits it into fragments,
 * then injects the encoded data via the injectMessage: delegate method.
 *
 * @param message		The message to be encoded
 * @param tlvs			Array of OTRTLVs, the data length of each TLV must be smaller than UINT16_MAX or it will be ignored.
 * @param username		The account name of the remote user
 * @param accountName	The account name of the local user
 * @param protocol		The protocol of the exchange
 * @param asynchronously	Whether the operation is performed asynchronously
 * @param tag			Optional tag to attach additional application-specific data to message. Only used locally.
 */
- (void)encodeMessage:(nullable NSString *)message
				 tlvs:(nullable NSArray<OTRTLV *> *)tlvs
			 username:(NSString *)username
		  accountName:(NSString *)accountName
			 protocol:(NSString *)protocol
	   asynchronously:(BOOL)asynchronously
				  tag:(nullable id)tag;

/**
 *  All messages should be sent through here before being processed by your program.
 *
 *  @param message			Encoded or plain text incoming message
 *  @param username			The account name of the remote user
 *  @param accountName		The account name of the local user
 *  @param protocol			The protocol of the exchange
 *  @param asynchronously	Whether the operation is performed asynchronously
 *  @param tag				Optional tag to attach additional application-specific data to message. Only used locally.
 */
- (void)decodeMessage:(NSString *)message
			 username:(NSString *)username
		  accountName:(NSString *)accountName
			 protocol:(NSString *)protocol
	   asynchronously:(BOOL)asynchronously
				  tag:(nullable id)tag;

/**
 *  You can use this method to determine whether or not OTRKit is 
 *  currently generating a private key.
 *
 *  @param accountName		The account name of the local user
 *  @param protocol			The protocol of the exchange
 */
- (BOOL)isGeneratingKeyForAccountName:(NSString *)accountName
							 protocol:(NSString *)protocol;

/**
 *  Shortcut for injecting a "?OTR?" message.
 *
 *  @param username			The account name of the remote user
 *  @param accountName		The account name of the local user
 *  @param protocol			The protocol of the exchange
 *  @param asynchronously	Whether the operation is performed asynchronously
 */
- (void)initiateEncryptionWithUsername:(NSString *)username
						   accountName:(NSString *)accountName
							  protocol:(NSString *)protocol
						asynchronously:(BOOL)asynchronously;

/**
 *  Disable encryption and inform remote user you no longer wish to 
 *  communicate privately.
 *
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 */
- (void)disableEncryptionWithUsername:(NSString *)username
						  accountName:(NSString *)accountName
							 protocol:(NSString *)protocol;

/**
 *  Current encryption state for conversation.
 *
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 */
- (OTRKitMessageState)messageStateForUsername:(NSString *)username
								  accountName:(NSString *)accountName
									 protocol:(NSString *)protocol;

/**
 *  Current offer state for conversation.
 *
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 */
- (OTRKitOfferState)offerStateForUsername:(NSString *)username
							  accountName:(NSString *)accountName
								 protocol:(NSString *)protocol;

/**
 *  Return type of message.
 */
- (OTRKitMessageType)typeOfMessage:(NSString *)message;

//////////////////////////////////////////////////////////////////////
/// @name Socialist's Millionaire Protocol
//////////////////////////////////////////////////////////////////////

/**
 *  Initiate a Socialist Millionaire Problem (SMP) with shared secret to verify identity.
 *
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 *  @param secret		The secret must match exactly between users
 */
- (void)initiateSMPForUsername:(NSString *)username
				   accountName:(NSString *)accountName
					  protocol:(NSString *)protocol
						secret:(NSString *)secret;

/**
 *  Initiate a Socialist Millionaire Problem (SMP) with shared secret to verify identity.
 *
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 *  @param question		A question to ask the remote user
 *  @param secret		The secret must match exactly between users
 */
- (void)initiateSMPForUsername:(NSString *)username
				   accountName:(NSString *)accountName
					  protocol:(NSString *)protocol
					  question:(NSString *)question
						secret:(NSString *)secret;

/**
 *  Respond to an Socialist Millionaire Problem (SMP) request with the secret answer.
 *
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 *  @param secret      The secret must match exactly between users
 */
- (void)respondToSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
						 secret:(NSString *)secret;

/**
 *  Abort an open Socialist Millionaire Problem (SMP) request.
 *
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (void)abortSMPForUsername:(NSString *)username
				accountName:(NSString *)accountName
				   protocol:(NSString *)protocol;

//////////////////////////////////////////////////////////////////////
/// @name Shared Symmetric Key
//////////////////////////////////////////////////////////////////////

/**
 *  Requests a symmetric key for out-of-band crypto like file transfer.
 *
 *  @param username		The account name of the remote user
 *  @param accountName	The account name of the local user
 *  @param protocol		The protocol of the exchange
 *  @param use			Integer tag describing the use of the key
 *  @param useData		Any extra data that may be required to use the key
 *  @param completion	Symmetric key ready to be used externally, or error.
 */

- (void)requestSymmetricKeyForUsername:(NSString *)username
						   accountName:(NSString *)accountName
							  protocol:(NSString *)protocol
								forUse:(NSUInteger)use
							   useData:(NSData *)useData
							completion:(void (^)(NSData * __nullable key, NSError * __nullable error))completion;

//////////////////////////////////////////////////////////////////////
/// @name Fingerprint Verification
//////////////////////////////////////////////////////////////////////

/**
 *  Returns an array of OTRKitConcreteObject objects
 */
@property (nonatomic, readonly, copy) NSArray<OTRKitConcreteObject *> *requestAllFingerprints;

/**
 *  Delete a specified fingerprint.
 *
 *  @param fingerprint Fingerprint to delete
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (void)deleteFingerprint:(NSString *)fingerprint
				 username:(NSString *)username
			  accountName:(NSString *)accountName
				 protocol:(NSString *)protocol;

/**
 *  Delete a specified fingerprint.
 *
 *  @param fingerprint Fingerprint concrete object
 */
- (void)deleteFingerprintWithConcreteObject:(OTRKitConcreteObject *)fingerprint;

/**
 *  For determining the fingerprint of the local user.
 *
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (nullable NSString *)fingerprintForAccountName:(NSString *)accountName
										protocol:(NSString *)protocol;

/**
 *  For determining the fingerprint of a remote user.
 *
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (nullable NSString *)activeFingerprintForUsername:(NSString *)username
										accountName:(NSString *)accountName
										   protocol:(NSString *)protocol;

/**
 *  Whether or not the remote user's fingerprint is marked as verified.
 *
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
- (BOOL)activeFingerprintIsVerifiedForUsername:(NSString *)username
								   accountName:(NSString *)accountName
									  protocol:(NSString *)protocol;

/**
 *  Mark a user's active fingerprint as verified
 *
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 *  @param verified    Whether or not to trust this fingerprint
 */
- (void)setActiveFingerprintVerificationForUsername:(NSString *)username
										accountName:(NSString *)accountName
										   protocol:(NSString *)protocol
										   verified:(BOOL)verified;

/**
 *  Mark a user's active fingerprint as verified
 *
 *  @param fingerprint Fingerprint concrete object
 *  @param verified    Whether or not to trust this fingerprint
 */

- (void)setFingerprintVerificationForConcreteObject:(OTRKitConcreteObject *)fingerprint
										   verified:(BOOL)verified;

/**
 *  Test if a string starts with "?OTR".
 *
 *  @param string string to test
 *
 *  @return [string hasPrefix:@"?OTR"]
 */
+ (BOOL)stringStartsWithOTRPrefix:(NSString *)string;

/**
 *  Current library versions
 */
+ (NSString *)libotrVersion;
+ (NSString *)libgcryptVersion;
+ (NSString *)libgpgErrorVersion;

/**
 *  Return right portion of accountName as dictated by -accountNameSeparator
 */
- (nullable NSString *)rightPortionOfAccountName:(NSString *)accountName;

/**
 *  Return left portion of accountName as dictated by -accountNameSeparator
 */
- (nullable NSString *)leftPortionOfAccountName:(NSString *)accountName;
@end

NS_ASSUME_NONNULL_END
