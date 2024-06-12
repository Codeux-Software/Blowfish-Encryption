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

NS_ASSUME_NONNULL_BEGIN

@implementation OTRKitAuthenticationDialog

#pragma mark -
#pragma mark Dialog Factory

+ (void)requestAuthenticationForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

	OTRKitAuthenticationDialog *openDialog =
	[[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																   accountName:accountName
																	  protocol:protocol];

	if ( openDialog) {
		[openDialog _bringHostWindowForward];
	} else {
		openDialog = [OTRKitAuthenticationDialogOutgoing new];

		openDialog.cachedUsername = username;
		openDialog.cachedAccountName = accountName;
		openDialog.cachedProtocol = protocol;

		[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:openDialog];

		[(OTRKitAuthenticationDialogOutgoing *)openDialog _authenticateUser];
	}
}

+ (BOOL)handleAuthenticationRequest:(OTRKitSMPEvent)event progress:(double)progress question:(nullable NSString *)question username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

	OTRKitAuthenticationDialog *openDialog =
	[[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																   accountName:accountName
																	  protocol:protocol];

	if (event == OTRKitSMPEventAskForAnswer || event == OTRKitSMPEventAskForSecret) {
		if (openDialog) {
			if (openDialog.isIncomingRequest == NO) {
				[[OTRKit sharedInstance] abortSMPForUsername:username
												 accountName:accountName
													protocol:protocol];
			}

			[openDialog _presentAuthenticationRequestAlreadyExistsAlert];

			return NO; // Do not further event...
		}
	} else {
		/* All other events */
		/* If we have no open dialog already and receive an event that isn't
		 asking us a question or for a secret, then we have no reason to
		 respond to it. We will pretend like it was a mistake. */

		if (openDialog == nil) {
			return NO;
		}
	}

	if (openDialog == nil) {
		openDialog = [OTRKitAuthenticationDialogIncoming new];

		openDialog.cachedUsername = username;
		openDialog.cachedAccountName = accountName;
		openDialog.cachedProtocol = protocol;

		[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:openDialog];
	}

	[openDialog _handleEvent:event progress:progress question:question];

	return YES;
}

+ (void)showFingerprintConfirmation:(NSWindow *)hostWindow username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(hostWindow != nil);
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

	[OTRKitAuthenticationDialogOutgoing showFingerprintConfirmation:hostWindow username:username accountName:accountName protocol:protocol];
}

+ (void)cancelRequestForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

	OTRKitAuthenticationDialog *openDialog =
	[[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																   accountName:accountName
																	  protocol:protocol];

	if ( openDialog) {
		[openDialog _cancelRequest];
	}
}

#pragma mark -
#pragma mark Dialog Construction

- (instancetype)init
{
	if ((self = [super init])) {
		[self _prepareInitialState];

		return self;
	}

	return nil;
}

- (void)_prepareInitialState
{
	/* Observe notifications for when the application will terminate so that we can
	 tear down the dialog gracefully instead of allowing OS X to shove its memory aside. */
	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_applicationWillTerminateNotification:) name:NSApplicationWillTerminateNotification object:nil];
}

- (void)_applicationWillTerminateNotification:(NSNotification *)notification
{
	/* Invoke -cancelRequest so that an abort signal can be sent if it must. */
	[self _cancelRequest];
}

- (void)_bringHostWindowForward
{
	[self.authenticationHostWindow makeKeyAndOrderFront:nil];
}

- (void)_changeContentViewTo:(NSView *)contentView
{
	NSParameterAssert(contentView != nil);

	/* Remove any views that may already be in place. */
	NSArray *contentSubviews = self.contentView.subviews;

	if (contentSubviews.count > 0) {
		[contentSubviews[0] removeFromSuperview];
	}

	/* Set constraints and add the new view. */
	[self.contentView addSubview:contentView];

	[self.contentView addConstraints:
	 [NSLayoutConstraint constraintsWithVisualFormat:@"H:|-0-[contentView]-0-|"
											 options:NSLayoutFormatDirectionLeadingToTrailing
											 metrics:nil
											   views:NSDictionaryOfVariableBindings(contentView)]];

	[self.contentView addConstraints:
	 [NSLayoutConstraint constraintsWithVisualFormat:@"V:|-0-[contentView]-0-|"
											 options:NSLayoutFormatDirectionLeadingToTrailing
											 metrics:nil
											   views:NSDictionaryOfVariableBindings(contentView)]];
}

- (void)_formatTextField:(NSTextField *)textField withUsername:(NSString *)username
{
	NSParameterAssert(textField != nil);
	NSParameterAssert(username != nil);

	/* Many text fields contain a formatting character (%@) in the interface. This
	 takes that text field value and formats it using the given username. Easier 
	 doing it this way than maintaining a strings file. */
	NSString *currentTextFieldValue = textField.stringValue;

	NSString *formattedStringValue = [NSString stringWithFormat:currentTextFieldValue, username];

	textField.stringValue = formattedStringValue;
}

- (void)_updateButtonEnabledState
{
	/* Update the Ok and Cancel buttons of the host window depending on values. */
	/* When sent, the values in the text field are not trimmed of whitespaces, but
	 we do it below to try and check validity as best as possible. */
	BOOL okButtonEnabled = YES;

	if (self.authenticationMethod == OTRKitSMPEventAskForAnswer)
	{
		NSString *question = self.questionAndAnswerQuestionTextField.stringValue;
		NSString *answer = self.questionAndAnswerAnswerTextField.stringValue;

		NSString *trimmedQuestion = [question stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];;
		NSString *trimmedAnswer = [answer stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

		okButtonEnabled = (trimmedQuestion.length > 0 &&
						   trimmedAnswer.length > 0);
	}
	else if (self.authenticationMethod == OTRKitSMPEventAskForSecret)
	{
		NSString *secret = self.sharedSecretAnswerTextField.stringValue;

		NSString *trimmedSecret = [secret stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

		okButtonEnabled = (trimmedSecret.length > 0);
	}

	/* Update buttons with their status. */
	self.authenticationHostWindowAuthenticateButton.enabled = okButtonEnabled;

	self.authenticationHostWindowCancelButton.enabled = YES;
}

- (void)controlTextDidChange:(NSNotification *)notification
{
	[self _updateButtonEnabledState];
}

#pragma mark -
#pragma mark Dialog Actions 

- (void)_cancelAuthentication:(id)sender
{
	;
}

- (void)_performAuthentication:(id)sender
{
	;
}

#pragma mark -
#pragma mark Alert Construction

- (void)_presentAlert:(NSString *)messageText informativeText:(NSString *)informativeText buttons:(nullable NSArray *)buttons completionBlock:(nullable OTRKitAlertDialogCompletionBlock)completionBlock
{
	NSParameterAssert(messageText != nil);
	NSParameterAssert(informativeText != nil);

	if (buttons == nil || buttons.count == 0) {
		buttons = @[_LocalizedString(@"00012")]; // "OK" label
	}

	[OTRKitFrameworkHelpers presentAlertInWindow:self.authenticationHostWindow
									 messageText:messageText
								 informativeText:informativeText
										 buttons:buttons
									 contextInfo:nil
								 completionBlock:completionBlock];
}

- (void)_presentPrivateConversationIsNotActiveAlert
{
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedUsername];

	NSString *messageText = _LocalizedString(@"00013[1]", username);

	NSString *descriptionText = _LocalizedString(@"00013[2]");

	[self _presentAlert:messageText
		informativeText:descriptionText
				buttons:nil
		completionBlock:nil];
}

- (void)_presentAuthenticationRequestAlreadyExistsAlert
{
	/* Do not show alert multiple times */
	if (self.authenticationRequestAlreadyExistsAlertIsVisible == NO) {
		self.authenticationRequestAlreadyExistsAlertIsVisible = YES;
	} else {
		return; // Cancel operation...
	}

	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedUsername];

	NSString *messageText = _LocalizedString(@"00010[1]", username);

	NSString *descriptionText = _LocalizedString(@"00010[2]");

	[self _presentAlert:messageText
		informativeText:descriptionText
				buttons:nil
		completionBlock:nil];
}

- (void)_presentRemoteUserAbortedAuthenticationRequestAlert
{
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedUsername];

	NSString *messageText = _LocalizedString(@"00011[1]", username);

	NSString *descriptionText = _LocalizedString(@"00011[2]");

	[[OTRKitAuthenticationDialogWindowManager sharedManager] markDialogAsStale:self];

	[self _presentAlert:messageText
		informativeText:descriptionText
				buttons:nil
		completionBlock:^(NSInteger buttonClicked, id contextInfo) {
		 if (buttonClicked == NSAlertFirstButtonReturn) {
			 [self _teardownDialog];
		 }
	 }];
}

#pragma mark -
#pragma mark Dialog Helpers

- (void)_markUserVerified:(BOOL)isVerified
{
	[[OTRKit sharedInstance] setActiveFingerprintVerificationForUsername:self.cachedUsername
															 accountName:self.cachedAccountName
																protocol:self.cachedProtocol
																verified:isVerified];
}

#pragma mark -
#pragma mark Teardown Dialog

- (void)_maybeAbortOpenNegotiations
{
	if (self.lastEvent == OTRKitSMPEventInProgress ||
		self.lastEvent == OTRKitSMPEventAskForAnswer ||
		self.lastEvent == OTRKitSMPEventAskForSecret)
	{
		[[OTRKit sharedInstance] abortSMPForUsername:self.cachedUsername
										 accountName:self.cachedAccountName
											protocol:self.cachedProtocol];
	}
}

- (void)_cancelRequest
{
	[self _maybeAbortOpenNegotiations];

	[self _teardownDialog];
}

- (void)_teardownDialog
{
	[[NSNotificationCenter defaultCenter] removeObserver:self];

	[self _endProgressIndicatorWindow];

	[self _closeHostWindow];

	[[OTRKitAuthenticationDialogWindowManager sharedManager] removeDialog:self];
}

- (void)_closeHostWindow
{
	/* Close the host window if visible. */
	if (self.authenticationHostWindow.visible) {
		[self.authenticationHostWindow close];
	}
}

#pragma mark -
#pragma mark Progress Indicator

- (void)setLastEvent:(OTRKitSMPEvent)lastEvent
{
	/* Update last event and possibly progress information. */
	if (self->_lastEvent != lastEvent) {
		self->_lastEvent = lastEvent;

		if ([self _progressIndicatorWindowIsVisible]) {
			[self _updateProgressIndicatorButtonsWithEvent:lastEvent];
		}
	}
}

- (void)setAuthenticationMethod:(OTRKitSMPEvent)authenticationMethod
{
	/* Switch views when authentication method changes. */
	if (self->_authenticationMethod != authenticationMethod) {
		self->_authenticationMethod = authenticationMethod;

		if (authenticationMethod == OTRKitSMPEventNone) {
			[self _changeContentViewTo:self.contentViewFingerprintAuthentication];
		} else if (authenticationMethod == OTRKitSMPEventAskForAnswer) {
			[self _changeContentViewTo:self.contentViewQuestionAndAnswerAuthentication];
		} else if (authenticationMethod == OTRKitSMPEventAskForSecret) {
			[self _changeContentViewTo:self.contentViewSharedSecretAuthentication];
		} else {
			NSAssert(NO, @"Bad authenticationMethod value");
		}
	}
}

- (void)_handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(nullable NSString *)question
{
	self.lastEvent = event;

	if ([self _progressIndicatorWindowIsVisible]) {
		[self _updateProgressIndicatorPercentage:progress];
	}
}

- (BOOL)_progressIndicatorWindowIsVisible
{
	return (self.authenticationProgressWindow.sheet &&
			self.authenticationProgressWindow.visible);
}

- (void)_setupProgressIndicatorWindow
{
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedUsername];

	[self _formatTextField:self.authenticationProgressTitleTextField withUsername:username];

	self.authenticationProgressProgressIndicator.doubleValue = 0.0;

	[self.authenticationHostWindow beginSheet:self.authenticationProgressWindow
							completionHandler:^(NSModalResponse returnCode) {
		[self _authenticationProgressWindowSheetDidEnd];
	}];

	self.lastEvent = OTRKitSMPEventInProgress;
}

- (void)_authenticationProgressWindowSheetDidEnd
{
	;
}

- (void)_updateProgressIndicatorStatusMessage:(NSString *)statusMessage
{
	self.authenticationProgressStatusTextField.stringValue = statusMessage;
}

- (void)_updateProgressIndicatorPercentage:(double)progress
{
	self.authenticationProgressProgressIndicator.doubleValue = progress;
}

- (void)_updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event
{
	/* Update progress status based on given event. */
	BOOL enableOkButton = NO;
	BOOL enableCancelButton = NO;

	switch (event) {
		case OTRKitSMPEventCheated:
		case OTRKitSMPEventError:
		{
			enableOkButton = YES;

			[self _updateProgressIndicatorStatusMessage:_LocalizedString(@"00005")];

			break;
		}
		case OTRKitSMPEventInProgress:
		{
			enableCancelButton = YES;

			[self _updateProgressIndicatorStatusMessage:_LocalizedString(@"00001")];

			break;
		}
		case OTRKitSMPEventFailure:
		{
			enableOkButton = YES;

			[self _updateProgressIndicatorStatusMessage:_LocalizedString(@"00003")];

			break;
		}
		case OTRKitSMPEventAbort:
		{
			enableOkButton = YES;

			[self _updateProgressIndicatorStatusMessage:_LocalizedString(@"00004")];

			break;
		}
		case OTRKitSMPEventSuccess:
		{
			enableOkButton = YES;

			[self _updateProgressIndicatorStatusMessage:_LocalizedString(@"00002")];

			break;
		}
		default:
		{
			break;
		}
	}

	self.authenticationProgressOkButton.enabled = enableOkButton;
	self.authenticationProgressCancelButton.enabled = enableCancelButton;
}

- (void)_endProgressIndicatorWindow
{
	/* Close the current progress window if open. */
	if ([self _progressIndicatorWindowIsVisible]) {
		[self.authenticationHostWindow endSheet:self.authenticationProgressWindow];
	}
}

- (IBAction)_authenticationProgressCancel:(id)sender
{
	/* Close negotiation if it is open. */
	[self _maybeAbortOpenNegotiations];

	/* There is no way to resend failed requests for incoming. */
	if (self.isIncomingRequest) {
		[self _teardownDialog];
	} else {
		[self _endProgressIndicatorWindow];
	}
}

- (IBAction)_authenticationProgressOk:(id)sender
{
	/* If the last event was successful, then we can tear down the entire
	 dialog, not just the progress indicator, because we are done here. */
	if (self.lastEvent == OTRKitSMPEventSuccess) {
		[self _teardownDialog]; // Will close progress window for us...

		return;
	}

	/* There is no way to resend failed requests for incoming. */
	if (self.isIncomingRequest) {
		[self _teardownDialog];
	} else {
		[self _endProgressIndicatorWindow];
	}
}

@end

NS_ASSUME_NONNULL_END
