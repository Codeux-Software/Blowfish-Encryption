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

#import <EncryptionKit/OTRKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface OTRKitAuthenticationDialog : NSObject

/**
 *  Request authentication of a remote user using a Socialist Millionaire Problem (SMP)
 *
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
+ (void)requestAuthenticationForUsername:(NSString *)username
							 accountName:(NSString *)accountName
								protocol:(NSString *)protocol;

/**
 *  Respond to a Socialist Millionaire Problem (SMP)
 * 
 *  @param event		The type of event
 *  @param progress		Percent progress of the negotiation
 *  @param question		Question that should be displayed to user
 *  @param username     The account name of the remote user
 *  @param accountName  The account name of the local user
 *  @param protocol     The protocol of the exchange
 *  
 *  @return YES on successfully handling event
 */
+ (BOOL)handleAuthenticationRequest:(OTRKitSMPEvent)event
						   progress:(double)progress
						   question:(nullable NSString *)question
						   username:(NSString *)username
						accountName:(NSString *)accountName
						   protocol:(NSString *)protocol;

/**
 *  Show a dialog so the user can confirm when a user's fingerprint changes.
 *
 *  @param hostWindow  A window the confirmation sheet can be attached to.
 *  @param username    The account name of the remote user
 *  @param accountName The account name of the local user
 *  @param protocol    The protocol of the exchange
 */
+ (void)showFingerprintConfirmation:(NSWindow *)hostWindow
						   username:(NSString *)username
						accountName:(NSString *)accountName
						   protocol:(NSString *)protocol;

/**
 *  Cancel all progress and close the dialog.
 *
 *  This method automatically aborts any open negotiations on behalf of the caller.
 */
+ (void)cancelRequestForUsername:(NSString *)username
					 accountName:(NSString *)accountName
						protocol:(NSString *)protocol;
@end

NS_ASSUME_NONNULL_END
