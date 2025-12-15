import * as vscode from 'vscode';
import { PfxEditorProvider } from './pfxEditorProvider';

export function activate(context: vscode.ExtensionContext) {
	console.log('PFX Viewer extension is now active');

	// Register the custom editor provider for PFX/P12 files
	context.subscriptions.push(PfxEditorProvider.register(context));
}

export function deactivate() {}
