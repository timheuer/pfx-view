import * as vscode from 'vscode';
import { createLoggerFromConfig, Logger } from '@timheuer/vscode-ext-logger';
import { PfxEditorProvider } from './pfxEditorProvider';

// Global logger instance
export let logger: Logger;

export function activate(context: vscode.ExtensionContext) {
	// Initialize logger from VS Code configuration with auto-monitoring
	logger = createLoggerFromConfig(
		context.extension.packageJSON.displayName,  // Logger name
		'pfx-view',                                  // Config section
		'logLevel',                                  // Config key
		'info',                                      // Default level
		true,                                        // Output channel
		context,                                     // Extension context
		true                                         // Enable config monitoring
	);

	logger.info('Extension activated');

	// Register the custom editor provider for PFX/P12 files
	context.subscriptions.push(PfxEditorProvider.register(context));
}

export function deactivate() {
	logger?.dispose();
}
