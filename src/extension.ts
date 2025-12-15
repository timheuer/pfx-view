import * as vscode from 'vscode';
import { Logger } from '@timheuer/vscode-ext-logger';
import { PfxEditorProvider } from './pfxEditorProvider';

// Global logger instance
export let logger: Logger;

export function activate(context: vscode.ExtensionContext) {
	// Initialize logger with VS Code output channel
	logger = new Logger({
		name: context.extension.packageJSON.displayName,
		level: 'info',
		outputChannel: true,
		context: context
	});

	logger.info('Extension activated');

	// Register the custom editor provider for PFX/P12 files
	context.subscriptions.push(PfxEditorProvider.register(context));
}

export function deactivate() {
	logger?.dispose();
}
