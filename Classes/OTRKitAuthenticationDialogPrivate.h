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

#import "OTRKitAuthenticationDialog.h"
#import "OTRKitAuthenticationDialogWindowManager.h"

#import "OTRKitFrameworkHelpers.h"

#import "OTRKitAutoExpandingTextField.h"

NS_ASSUME_NONNULL_BEGIN

#define _LocalizedString(_key_, ...)				\
	LocalizedString(@"OTRKitAuthenticationDialog", (_key_), ##__VA_ARGS__)

#pragma mark -
#pragma mark Headers

@interface OTRKitAuthenticationDialog ()
@property (nonatomic, copy) NSString *cachedUsername;
@property (nonatomic, copy) NSString *cachedAccountName;
@property (nonatomic, copy) NSString *cachedProtocol;
@property (readonly) BOOL isIncomingRequest;
@property (nonatomic, assign) BOOL authenticationRequestAlreadyExistsAlertIsVisible;
@property (nonatomic, assign) OTRKitSMPEvent lastEvent;
@property (nonatomic, assign) OTRKitSMPEvent authenticationMethod; // none = fingerprint, question & answer, or shared secret
@property (nonatomic, weak) IBOutlet NSView *contentView;
@property (nonatomic, strong) IBOutlet NSWindow *authenticationHostWindow;
@property (nonatomic, strong) IBOutlet NSWindow *authenticationProgressWindow;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationProgressTitleTextField;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationProgressStatusTextField;
@property (nonatomic, weak) IBOutlet NSButton *authenticationProgressOkButton;
@property (nonatomic, weak) IBOutlet NSButton *authenticationProgressCancelButton;
@property (nonatomic, weak) IBOutlet NSProgressIndicator *authenticationProgressProgressIndicator;
@property (nonatomic, strong, nullable) IBOutlet NSView *contentViewFingerprintAuthentication;
@property (nonatomic, strong) IBOutlet NSView *contentViewQuestionAndAnswerAuthentication;
@property (nonatomic, strong) IBOutlet NSView *contentViewSharedSecretAuthentication;
@property (nonatomic, weak) IBOutlet OTRKitAutoExpandingTextField *questionAndAnswerQuestionTextField;
@property (nonatomic, weak) IBOutlet OTRKitAutoExpandingTextField *questionAndAnswerAnswerTextField;
@property (nonatomic, weak) IBOutlet NSTextField *questionAndAnswerDescriptionTextField;
@property (nonatomic, weak) IBOutlet OTRKitAutoExpandingTextField *sharedSecretAnswerTextField;
@property (nonatomic, weak) IBOutlet NSTextField *sharedSecretDescriptionTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintLocalUserLabelTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintLocalUserValueTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintRemoteUserLabelTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintRemoteUserValueTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintDescriptionTextField;
@property (nonatomic, weak) IBOutlet NSButton *authenticationHostWindowCancelButton;
@property (nonatomic, weak) IBOutlet NSButton *authenticationHostWindowAuthenticateButton;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationHostWindowTitleTextField;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationHostWindowDescriptionTextField;

- (IBAction)_cancelAuthentication:(id)sender;
- (IBAction)_performAuthentication:(id)sender;

- (IBAction)_authenticationProgressCancel:(id)sender;
- (IBAction)_authenticationProgressOk:(id)sender;

- (void)_updateButtonEnabledState;
- (void)_formatTextField:(NSTextField *)textField withUsername:(NSString *)username;
- (void)_changeContentViewTo:(NSView *)contentView;
- (void)_bringHostWindowForward;

- (void)_prepareInitialState;

- (void)_markUserVerified:(BOOL)isVerified;

- (void)_presentPrivateConversationIsNotActiveAlert;
- (void)_presentAuthenticationRequestAlreadyExistsAlert;
- (void)_presentRemoteUserAbortedAuthenticationRequestAlert;

- (void)_cancelRequest;
- (void)_teardownDialog;

- (void)_handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(nullable NSString *)question;

- (void)_setupProgressIndicatorWindow;
- (BOOL)_progressIndicatorWindowIsVisible;
- (void)_updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event;
@end

#pragma mark -

@interface OTRKitAuthenticationDialogIncoming : OTRKitAuthenticationDialog
@end

#pragma mark -

@interface OTRKitAuthenticationDialogOutgoing : OTRKitAuthenticationDialog <NSTextFieldDelegate>
@property (nonatomic, weak) IBOutlet NSPopUpButton *authenticationMethodSelectionPopupButton;
@property (nonatomic, weak) IBOutlet NSButton *fingerprintIsVerifiedUserCheck;

- (void)_authenticateUser;

- (IBAction)_authenticationMethodChanged:(id)sender;
@end

NS_ASSUME_NONNULL_END
