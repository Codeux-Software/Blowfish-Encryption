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

#import "OTRKitAuthenticationDialogPrivate.h"

#import "OTRKitConcreteObjectPrivate.h"

NS_ASSUME_NONNULL_BEGIN

@implementation OTRKitAuthenticationDialogOutgoing

static NSMutableArray *_listOfOpenFingerprintConfirmationAlerts = nil;

- (void)_prepareInitialState
{
    [[NSBundle bundleForClass:self.class]  loadNibNamed:@"OTRKitAuthenticationDialogOutgoing" owner:self topLevelObjects:nil];

    [super _prepareInitialState];
}

- (BOOL)isIncomingRequest
{
    return NO;
}

- (void)_cancelAuthentication:(id)sender
{
    [self _teardownDialog];
}

- (void)_performAuthentication:(id)sender
{
    /* Check the message state for this user. */
    OTRKitMessageState messageState = [[OTRKit sharedInstance] messageStateForUsername:self.cachedUsername
                                                                           accountName:self.cachedAccountName
                                                                              protocol:self.cachedProtocol];

    if (messageState == OTRKitMessageStateFinished ||
        messageState == OTRKitMessageStatePlaintext)
    {
        [self _presentPrivateConversationIsNotActiveAlert];

        return; // Cancel operation...
    }

    /* Start a negotiation depending on which method was selected. */
    if (self.authenticationMethod == OTRKitSMPEventNone)
    {
        BOOL isVerified = (self.fingerprintIsVerifiedUserCheck.state == NSOnState);

        [self _markUserVerified:isVerified];

        [self _teardownDialog];
    }
    else if (self.authenticationMethod == OTRKitSMPEventAskForAnswer)
    {
        NSString *question = self.questionAndAnswerQuestionTextField.stringValue;
        NSString *answer = self.questionAndAnswerAnswerTextField.stringValue;

        [[OTRKit sharedInstance] initiateSMPForUsername:self.cachedUsername
                                            accountName:self.cachedAccountName
                                               protocol:self.cachedProtocol
                                               question:question
                                                 secret:answer];

        [self _setupProgressIndicatorWindow];
    }
    else if (self.authenticationMethod == OTRKitSMPEventAskForSecret)
    {
        NSString *secret = self.sharedSecretAnswerTextField.stringValue;

        [[OTRKit sharedInstance] initiateSMPForUsername:self.cachedUsername
                                            accountName:self.cachedAccountName
                                               protocol:self.cachedProtocol
                                                 secret:secret];

        [self _setupProgressIndicatorWindow];
    }
}

- (void)_authenticationMethodChanged:(id)sender
{
    /* Change to a different authentication method. */
    NSInteger selectedItem = self.authenticationMethodSelectionPopupButton.selectedTag;

    if (selectedItem == 0) {
        self.authenticationMethod = OTRKitSMPEventAskForAnswer;
    } else if (selectedItem == 1) {
        self.authenticationMethod = OTRKitSMPEventAskForSecret;
    } else if (selectedItem == 2) {
        self.authenticationMethod = OTRKitSMPEventNone;
    }

    [self _updateButtonEnabledState];
}

- (void)_updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event
{
    [super _updateProgressIndicatorButtonsWithEvent:event];

    if (event == OTRKitSMPEventSuccess) {
        [self _markUserVerified:YES]; // Mark user as trusted.
    } else if (event == OTRKitSMPEventFailure) {
        [self _markUserVerified:NO]; // Mark user as trusted.
    }
}

+ (void)showFingerprintConfirmation:(NSWindow *)hostWindow username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(hostWindow != nil);
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

    OTRKitConcreteObject *concreteObject = [OTRKitConcreteObject new];

    concreteObject.username = username;
    concreteObject.accountName = accountName;
    concreteObject.protocol = protocol;

    /* An array of open alerts is kept track of (even though there should never be 
     more than one) to prepare for any funny business. */
    @synchronized (_listOfOpenFingerprintConfirmationAlerts) {
		if (_listOfOpenFingerprintConfirmationAlerts == nil) {
			_listOfOpenFingerprintConfirmationAlerts = [NSMutableArray array];
		}

        if ([_listOfOpenFingerprintConfirmationAlerts containsObject:concreteObject] == NO) {
			[_listOfOpenFingerprintConfirmationAlerts addObject:concreteObject];
        } else {
            return;
        }
    }

    NSString *remoteUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:username];

    NSString *messageText = _LocalizedString(@"00012[1]", remoteUsername);

    NSString *descriptionText = _LocalizedString(@"00012[2]");

    NSArray *alertButtons = @[_LocalizedString(@"00012[3]"),
                              _LocalizedString(@"00012[4]")];

    [OTRKitFrameworkHelpers presentAlertInWindow:hostWindow
                                     messageText:messageText
                                 informativeText:descriptionText
                                         buttons:alertButtons
                                     contextInfo:concreteObject
                                 completionBlock:^(NSInteger buttonClicked, id contextInfo) {
                                     [self _showFingerprintConfirmationAlertDidEnd:buttonClicked contextInfo:contextInfo];
                                 }];
}

+ (void)_showFingerprintConfirmationAlertDidEnd:(NSInteger)buttonClicked contextInfo:(OTRKitConcreteObject *)contextInfo
{
    /* Check which button the user clicked */
    if (buttonClicked != NSAlertFirstButtonReturn) {
        return;
    }

    /* Request authentication */
    [OTRKitAuthenticationDialog requestAuthenticationForUsername:contextInfo.username
                                                     accountName:contextInfo.accountName
                                                        protocol:contextInfo.protocol];

    /* Remove reference in list of open alerts */
    @synchronized (_listOfOpenFingerprintConfirmationAlerts) {
		[_listOfOpenFingerprintConfirmationAlerts removeObject:contextInfo];
    }
}

- (void)_authenticateUser
{
    /* Reset state just to be safe. */
    self.lastEvent = OTRKitSMPEventNone;

    /* Set default content view which is Question & Answer */
    self.authenticationMethod = OTRKitSMPEventAskForAnswer;

    /* Get the visible portion of the remote user's name. */
    NSString *remoteUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedUsername];
    NSString *localUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedAccountName];

    /* Format several text fields with the user's name. */
    [self _formatTextField:self.fingerprintLocalUserLabelTextField withUsername:localUsername];
    [self _formatTextField:self.fingerprintRemoteUserLabelTextField withUsername:remoteUsername];

    [self _formatTextField:self.authenticationHostWindowTitleTextField withUsername:remoteUsername];

    /* Gather existing fingerprint information */
    NSString *localFingerprint = [[OTRKit sharedInstance] fingerprintForAccountName:self.cachedAccountName
                                                                           protocol:self.cachedProtocol];

    NSString *remoteFingerprint = [[OTRKit sharedInstance] activeFingerprintForUsername:self.cachedUsername
                                                                            accountName:self.cachedAccountName
                                                                               protocol:self.cachedProtocol];

    /* Determine whether the user's fingerprint is already trusted. */
    BOOL remoteFingerprintTrusted = [[OTRKit sharedInstance] activeFingerprintIsVerifiedForUsername:self.cachedUsername
                                                                                        accountName:self.cachedAccountName
                                                                                           protocol:self.cachedProtocol];

    /* Populate default values */
    self.fingerprintLocalUserValueTextField.stringValue = localFingerprint;
    self.fingerprintRemoteUserValueTextField.stringValue = remoteFingerprint;

    self.fingerprintIsVerifiedUserCheck.state = remoteFingerprintTrusted;

    /* Bring the trust dialog forward */
    [self _updateButtonEnabledState];

    [self _bringHostWindowForward];
}

@end

NS_ASSUME_NONNULL_END
