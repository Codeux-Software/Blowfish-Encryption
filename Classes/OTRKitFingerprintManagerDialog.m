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

#import "OTRKitFingerprintManagerDialogPrivate.h"

NS_ASSUME_NONNULL_BEGIN

@implementation OTRKitFingerprintManagerDialog

#pragma mark -
#pragma mark Public Methods

- (instancetype)init
{
	if ((self = [super init])) {
		[self _prepareInitialState];

		return self;
	}

	return nil;
}

- (void)dealloc
{
	self.delegate = nil;
}

- (void)_prepareInitialState
{
	[[NSBundle bundleForClass:self.class] loadNibNamed:@"OTRKitFingerprintManagerDialog" owner:self topLevelObjects:nil];

	[self _populateFingerprintCache];

	[self _updateButtonsEnabledState];

	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_applicationWillTerminateNotification:) name:NSApplicationWillTerminateNotification object:nil];

	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_noteFingerprintsChanged:) name:OTRKitListOfFingerprintsDidChangeNotification object:nil];
	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_noteFingerprintsChanged:) name:OTRKitMessageStateDidChangeNotification object:nil];
}

- (void)open
{
	[self open:nil];
}

- (void)open:(nullable NSWindow *)hostWindow
{
	if (self.isStale) {
		return;
	}

	if (hostWindow) {
		/* Do not open as sheet if already open as a sheet */
		if (self.fingerprintManagerWindow.sheet) {
			return;
		}

		[hostWindow beginSheet:self.fingerprintManagerWindow
			 completionHandler:^(NSModalResponse returnCode) {
			[self _fingerprintManagerWindowDidEndSheet];
		}];

		return;
	}

	/* Bring window forward */
	[self.fingerprintManagerWindow makeKeyAndOrderFront:nil];
}

- (void)_fingerprintManagerWindowDidEndSheet
{
	[self _closeStepTwo];
}

- (void)close
{
	if (self.isStale) {
		return;
	}

	NSWindow *hostWindow = self.fingerprintManagerWindow.sheetParent;

	if ( hostWindow) {
		[hostWindow endSheet:self.fingerprintManagerWindow];

		return;
	}

	if (self.fingerprintManagerWindow.visible) {
		[self.fingerprintManagerWindow close];

		[self _closeStepTwo];
	}
}

- (void)_closeStepTwo
{
	self.isStale = YES;

	[[NSNotificationCenter defaultCenter] removeObserver:self];

	if ( self.delegate) {
		[self.delegate otrKitFingerprintManagerDialogDidClose:self];
	}
}

- (IBAction)_closeDialog:(id)sender
{
	[self close];
}

- (void)_applicationWillTerminateNotification:(NSNotification *)notification
{
	[self close];
}

#pragma mark -
#pragma mark Table View

- (void)_noteFingerprintsChanged:(NSNotification *)notification
{
	[self _populateFingerprintCache];

	[self _reloadTable];
}

- (void)_populateFingerprintCache
{
	NSArray *fingerprints = [[OTRKit sharedInstance] requestAllFingerprints];

	self.cachedListOfFingerprints = fingerprints;
}

- (void)_reloadTable
{
	NSInteger currentSelection = [self _tableViewSelectedRow];

	[self.fingerprintListTable reloadData];

	/* If there is a selection and its within bounds of the number
	 of rows, then reselect it so the reload appears seamless */
	if (currentSelection >= 0) {
		if (self.fingerprintListTable.numberOfRows > currentSelection) {
			NSIndexSet *newSelection = [NSIndexSet indexSetWithIndex:currentSelection];

			[self.fingerprintListTable selectRowIndexes:newSelection byExtendingSelection:NO];
		} else {
			[self _updateButtonsEnabledState];
		}
	}
}

- (NSInteger)_tableViewSelectedRow
{
	return self.fingerprintListTable.selectedRow;
}

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
	return self.cachedListOfFingerprints.count;
}

- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row
{
	OTRKitFingerprintManagerDialogTableCellView *madeView = (id)[tableView makeViewWithIdentifier:tableColumn.identifier owner:self];

	/* Begin populating individual data sections. */
	OTRKitConcreteObject *rowEntryData = self.cachedListOfFingerprints[row];

	/* Populate username value */
	if ([tableColumn.identifier isEqual:@"username"]) {
		NSString *newValue = [[OTRKit sharedInstance] leftPortionOfAccountName:rowEntryData.username];

		madeView.textField.stringValue = newValue;
	}

	/* Populate account name value */
	else if ([tableColumn.identifier isEqual:@"accountName"])
	{
		NSString *newValue = [[OTRKit sharedInstance] leftPortionOfAccountName:rowEntryData.accountName];

		madeView.textField.stringValue = newValue;
	}

	/* Populate status value */
	else if ([tableColumn.identifier isEqual:@"status"])
	{
		BOOL isInUse = [self _isFingerprintActiveForObject:rowEntryData];

		if (isInUse) {
			[madeView.textField setStringValue:_LocalizedString(@"00001[2]")];
		} else {
			[madeView.textField setStringValue:_LocalizedString(@"00001[1]")];
		}
	}

	/* Populate trust value */
	else if ([tableColumn.identifier isEqual:@"trusted"])
	{
		BOOL isTrusted = rowEntryData.fingerprintIsTrusted;

		if (isTrusted) {
			madeView.viewCheckbox.state = NSOnState;
		} else {
			madeView.viewCheckbox.state = NSOffState;
		}

		madeView.viewCheckbox.tag = row;
	}

	/* Populate fingerprint value */
	else if ([tableColumn.identifier isEqual:@"fingerprint"])
	{
		NSString *newValue = rowEntryData.fingerprintString;

		madeView.textField.stringValue = newValue;
	}

	return madeView;
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification
{
	[self _updateButtonsEnabledState];
}

- (void)_updateButtonsEnabledState
{
	NSInteger currentSelection = [self _tableViewSelectedRow];

	if (currentSelection < 0 || self.cachedListOfFingerprints.count == 0)
	{
		self.buttonFingerprintForget.enabled = NO;

		self.buttonFingerprintEndConversation.hidden = YES;
	}
	else
	{
		OTRKitConcreteObject *dataObject = self.cachedListOfFingerprints[currentSelection];

		BOOL isFingerprintActive = [self _isFingerprintActiveForObject:dataObject];

		BOOL buttonCondition = (isFingerprintActive == NO);

		self.buttonFingerprintForget.enabled = buttonCondition;

		self.buttonFingerprintEndConversation.hidden = buttonCondition;
	}
}

- (BOOL)_isFingerprintActiveForObject:(OTRKitConcreteObject *)dataObject
{
	NSString *activeFingerprint = [[OTRKit sharedInstance] activeFingerprintForUsername:dataObject.username
																			accountName:dataObject.accountName
																			   protocol:dataObject.protocol];

	return ([dataObject.fingerprintString isEqual:activeFingerprint]);
}

#pragma mark -
#pragma mark Actions

- (IBAction)_fingerprintEndConversation:(id)sender
{
	OTRKitConcreteObject *dataObject = self.cachedListOfFingerprints[[self _tableViewSelectedRow]];

	[[OTRKit sharedInstance] disableEncryptionWithUsername:dataObject.username
											   accountName:dataObject.accountName
												  protocol:dataObject.protocol];
}

- (IBAction)_fingerprintForget:(id)sender
{
	OTRKitConcreteObject *dataObject = self.cachedListOfFingerprints[[self _tableViewSelectedRow]];

	[[OTRKit sharedInstance] deleteFingerprintWithConcreteObject:dataObject];
}

- (IBAction)_fingerprintModifyTrust:(id)sender
{
	OTRKitConcreteObject *dataObject = self.cachedListOfFingerprints[[sender tag]];

	BOOL isVerified = ([sender state] == NSOnState);

	[[OTRKit sharedInstance] setFingerprintVerificationForConcreteObject:dataObject
																verified:isVerified];
}

@end

#pragma mark -
#pragma mark Table View Helpers

@implementation OTRKitFingerprintManagerDialogTableCellView
@end

NS_ASSUME_NONNULL_END
