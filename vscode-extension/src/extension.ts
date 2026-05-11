import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as crypto from 'crypto';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

// ── IPC Security (SEC-02/03 FIX) ─────────────────────────────────────────────
// A random token is generated at extension startup and written to a
// user-only temp file.  The auditlens_runner.py reads this token and
// signs every message with HMAC-SHA256 so we can reject spoofed payloads.
const IPC_PORT = 9999;
let ipcToken: string = '';

function generateIpcToken(): string {
    return crypto.randomBytes(32).toString('hex');
}

function getTokenFilePath(): string {
    // Use process.getuid() when available (Unix); fall back on Windows.
    const uid = typeof (process as any).getuid === 'function'
        ? (process as any).getuid()
        : 'token';
    return path.join(os.tmpdir(), `auditlens_ipc_${uid}.key`);
}

function writeIpcToken(token: string) {
    const tokenFile = getTokenFilePath();
    try {
        fs.writeFileSync(tokenFile, token, { encoding: 'utf8', mode: 0o600 });
    } catch (e) {
        console.error('AuditLens: could not write IPC token file', e);
    }
}

function verifyIpcMessage(raw: string): any | null {
    try {
        const envelope = JSON.parse(raw.trim());
        if (!envelope.payload) return null;
        if (!ipcToken) return envelope.payload;  // token not set — degrade gracefully

        const expectedSig = crypto
            .createHmac('sha256', ipcToken)
            .update(JSON.stringify(envelope.payload))
            .digest('hex');

        if (envelope.sig !== expectedSig) {
            console.warn('AuditLens IPC: message signature mismatch — rejected.');
            return null;
        }
        return envelope.payload;
    } catch {
        return null;
    }
}

// ── Extension activation ──────────────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext) {
    console.log('AuditLens is now active.');
    vscode.window.showInformationMessage('AuditLens: Real-Time Security Scanner activated.');

    // UX-06 FIX: status bar indicator
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left, 100
    );
    statusBarItem.text = '$(shield) AuditLens';
    statusBarItem.tooltip = 'AuditLens Security Scanner';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    diagnosticCollection = vscode.languages.createDiagnosticCollection('auditlens');
    context.subscriptions.push(diagnosticCollection);

    // Generate and persist IPC token (SEC-02 FIX)
    ipcToken = generateIpcToken();
    writeIpcToken(ipcToken);

    // Scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const supportedLangs = ['python', 'javascript', 'typescript', 'swift', 'javascriptreact', 'typescriptreact'];
            if (supportedLangs.includes(document.languageId)) {
                runAuditLensScan(document);
            }
        })
    );

    // ── IPC Server (SEC-02/03 + CQ-10/11 FIX) ────────────────────────────────
    const ipcServer = net.createServer((socket) => {
        let buffer = '';

        socket.on('data', (data) => {
            // CQ-10 FIX: accumulate data across multiple TCP segments
            buffer += data.toString('utf8');

            // CQ-10 FIX: newline-delimited framing — process complete messages
            const lines = buffer.split('\n');
            buffer = lines.pop() ?? '';  // keep incomplete last segment

            for (const line of lines) {
                if (!line.trim()) continue;
                // SEC-02/03 FIX: verify HMAC signature before trusting content
                const message = verifyIpcMessage(line);
                if (!message) continue;

                if (message.type === 'crash_report') {
                    handleCrashReport(message);
                }
            }
        });

        socket.on('error', (err) => {
            console.error('AuditLens IPC socket error:', err.message);
        });
    });

    // CQ-11 FIX: handle port-in-use and other server errors gracefully
    ipcServer.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
            console.warn(
                `AuditLens: IPC port ${IPC_PORT} is already in use. ` +
                'Post-Mortem crash reporting will be unavailable.'
            );
        } else {
            console.error('AuditLens IPC server error:', err.message);
        }
    });

    ipcServer.listen(IPC_PORT, 'localhost', () => {
        console.log(`AuditLens IPC server listening on port ${IPC_PORT}`);
    });

    context.subscriptions.push({
        dispose: () => {
            ipcServer.close();
            // Clean up token file on deactivation
            try { fs.unlinkSync(getTokenFilePath()); } catch { /* ignore */ }
        }
    });

    // ── Commands ──────────────────────────────────────────────────────────────
    const runCommand = vscode.commands.registerCommand('auditlens.runPostMortem', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'python') {
            vscode.window.showErrorMessage('AuditLens: Open a Python file to use Run with AuditLens.');
            return;
        }

        const currentFile = editor.document.uri.fsPath;
        const pythonPath = vscode.workspace
            .getConfiguration('python')
            .get<string>('defaultInterpreterPath', 'python3');

        // BUG-05 FIX: resolve runner path relative to extension install directory,
        // not a hardcoded developer machine path.
        const runnerScript = context.asAbsolutePath(
            path.join('..', 'lsp-server', 'auditlens_runner.py')
        );

        if (!fs.existsSync(runnerScript)) {
            vscode.window.showErrorMessage(
                `AuditLens: Runner script not found at ${runnerScript}. ` +
                'Please reinstall the extension.'
            );
            return;
        }

        const terminal = vscode.window.createTerminal('AuditLens Run');
        terminal.show();
        terminal.sendText(`"${pythonPath}" "${runnerScript}" "${currentFile}"`);
    });

    context.subscriptions.push(runCommand);
}

// ── Crash report handler ──────────────────────────────────────────────────────
function handleCrashReport(message: any) {
    vscode.window.showErrorMessage(
        `AuditLens Post-Mortem: Crash in ${path.basename(message.file)}:${message.line}\n` +
        `${message.exception_type}: ${message.exception_message}\n` +
        `Code: ${message.code_context}`,
        { modal: true }
    );

    // SEC-03 FIX: validate that the file path is absolute and exists before opening
    const filePath: string = message.file ?? '';
    if (!path.isAbsolute(filePath) || !fs.existsSync(filePath)) {
        console.warn('AuditLens IPC: received non-existent or relative file path, ignoring.');
        return;
    }

    const openPath = vscode.Uri.file(filePath);
    vscode.workspace.openTextDocument(openPath).then(doc => {
        vscode.window.showTextDocument(doc).then(editor => {
            const linePos = new vscode.Position(Math.max(0, (message.line ?? 1) - 1), 0);
            editor.selection = new vscode.Selection(linePos, linePos);
            editor.revealRange(
                new vscode.Range(linePos, linePos),
                vscode.TextEditorRevealType.InCenter
            );
        });
    });
}

// ── Scan on save ──────────────────────────────────────────────────────────────
function runAuditLensScan(document: vscode.TextDocument) {
    const filePath = document.uri.fsPath;

    // UX-06 FIX: show scanning state in status bar
    statusBarItem.text = '$(sync~spin) AuditLens: Scanning...';

    // Resolve auditlens binary
    const auditlensPath = fs.existsSync('/opt/homebrew/bin/auditlens')
        ? '/opt/homebrew/bin/auditlens'
        : 'auditlens';

    // BUG-06 FIX: write SARIF to a per-file temp path so we never pollute the project
    const sarifPath = path.join(
        os.tmpdir(),
        `auditlens_${crypto.createHash('md5').update(filePath).digest('hex')}.sarif`
    );

    // BUG-07 FIX: delete stale SARIF file before running so we never read old results
    try { fs.unlinkSync(sarifPath); } catch { /* file may not exist — that's fine */ }

    const command = `${auditlensPath} scan "${filePath}" --format sarif --output "${sarifPath}" --no-sca`;

    cp.exec(command, { timeout: 30000 }, (error, _stdout, stderr) => {
        if (error && !fs.existsSync(sarifPath)) {
            // BUG-07 FIX: only surface an error when the SARIF file was not produced
            statusBarItem.text = '$(shield) AuditLens: Error';
            vscode.window.showErrorMessage(
                `AuditLens: Scan failed. ${stderr || error.message}`
            );
            return;
        }

        if (!fs.existsSync(sarifPath)) {
            statusBarItem.text = '$(shield) AuditLens';
            return;
        }

        try {
            const sarifContent = fs.readFileSync(sarifPath, 'utf8');
            const sarifData = JSON.parse(sarifContent);
            const count = updateDiagnostics(document, sarifData);

            // UX-06 FIX: show finding count in status bar
            if (count > 0) {
                statusBarItem.text = `$(warning) AuditLens: ${count} finding${count !== 1 ? 's' : ''}`;
            } else {
                statusBarItem.text = '$(pass) AuditLens: Clean';
            }
        } catch (e: any) {
            statusBarItem.text = '$(shield) AuditLens';
            vscode.window.showErrorMessage(`AuditLens: Error parsing SARIF: ${e.message}`);
        } finally {
            // Clean up temp SARIF file
            try { fs.unlinkSync(sarifPath); } catch { /* ignore */ }
        }
    });
}

// ── Diagnostics ───────────────────────────────────────────────────────────────
function updateDiagnostics(document: vscode.TextDocument, sarifData: any): number {
    diagnosticCollection.delete(document.uri);
    const diagnostics: vscode.Diagnostic[] = [];

    if (!sarifData.runs?.length) return 0;
    const results: any[] = sarifData.runs[0].results ?? [];

    for (const result of results) {
        const loc = result.locations?.[0]?.physicalLocation;
        if (!loc?.region) continue;

        const line = (loc.region.startLine ?? 1) - 1;  // SARIF 1-indexed → VS Code 0-indexed

        // UX-07 FIX: use actual column data from SARIF when available;
        // fall back to full-line range only when columns are missing.
        const startCol = (loc.region.startColumn ?? 1) - 1;
        const endCol = loc.region.endColumn
            ? loc.region.endColumn - 1
            : document.lineAt(Math.min(line, document.lineCount - 1)).text.length;

        const range = new vscode.Range(line, startCol, line, endCol);

        let severity = vscode.DiagnosticSeverity.Warning;
        if (result.level === 'error') {
            severity = vscode.DiagnosticSeverity.Error;
        } else if (result.level === 'note') {
            severity = vscode.DiagnosticSeverity.Information;
        }

        const message = `[${result.ruleId}] ${result.message?.text ?? ''}`;
        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'AuditLens';
        if (result.ruleId) {
            diagnostic.code = result.ruleId;
        }
        diagnostics.push(diagnostic);
    }

    diagnosticCollection.set(document.uri, diagnostics);
    return diagnostics.length;
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
    // Clean up IPC token file
    try { fs.unlinkSync(getTokenFilePath()); } catch { /* ignore */ }
}
