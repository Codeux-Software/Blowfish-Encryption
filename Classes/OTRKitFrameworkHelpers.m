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

#import "OTRKitFrameworkHelpers.h"

#include <objc/message.h>

NS_ASSUME_NONNULL_BEGIN

@implementation OTRKitFrameworkHelpers

+ (NSString *)localizedString:(NSString *)original inTable:(NSString *)inTable, ...
{
	NSParameterAssert(original != nil);
	NSParameterAssert(inTable != nil);

	va_list arguments;
	va_start(arguments, inTable);

	NSString *formattedString = [self localizedString:original inTable:inTable arguments:arguments];

	va_end(arguments);

	return formattedString;
}

+ (NSString *)localizedString:(NSString *)original inTable:(NSString *)inTable arguments:(va_list)arguments
{
	NSParameterAssert(original != nil);
	NSParameterAssert(inTable != nil);

	NSBundle *selfBundle = [NSBundle bundleForClass:[self class]];

	NSString *localeString = [selfBundle localizedStringForKey:original value:original table:inTable];

	NSString *formattedString = [[NSString alloc] initWithFormat:localeString arguments:arguments];

	return formattedString;
}

+ (NSWindow *)_deepestSheetOfWindow:(NSWindow *)window
{
	NSParameterAssert(window != nil);

	/* Recursively scan all attached sheets until we find a window without one. */
	NSWindow *attachedSheet = window.attachedSheet;

	if (attachedSheet) {
		return [self _deepestSheetOfWindow:attachedSheet];
	}

	return window;
}

+ (void)presentAlertInWindow:(nullable NSWindow *)hostWindow
				 messageText:(NSString *)messageText
			 informativeText:(NSString *)informativeText
					 buttons:(NSArray<NSString *> *)buttons
				 contextInfo:(nullable id)contextInfo
			 completionBlock:(nullable OTRKitAlertDialogCompletionBlock)completionBlock
{
	NSParameterAssert(messageText != nil);
	NSParameterAssert(informativeText != nil);
	NSParameterAssert(buttons != nil);

	/* Construct alert */
	NSAlert *errorAlert = [NSAlert new];

	errorAlert.alertStyle = NSAlertStyleInformational;

	errorAlert.messageText = messageText;
	errorAlert.informativeText = informativeText;

	for (NSString *button in buttons) {
		[errorAlert addButtonWithTitle:button];
	}

	/* Attach the sheet to the highest window */
	if (hostWindow) {
		hostWindow = [self _deepestSheetOfWindow:hostWindow];
	}

	if (hostWindow) {
		[errorAlert beginSheetModalForWindow:hostWindow
						   completionHandler:^(NSModalResponse returnCode) {
			if (completionBlock) {
				completionBlock(returnCode, contextInfo);
			}
		}];

		return;
	}

	NSModalResponse returnCode = [errorAlert runModal];

	if (completionBlock) {
		completionBlock(returnCode, contextInfo);
	}
}

@end

NS_ASSUME_NONNULL_END
