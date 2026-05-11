import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as crypto from 'crypto';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
const IPC_PORT = 9999;
let ipcToken = '';

// ── Debounce map — per-document open-scan timer ───────────────────────────────
const openScanTimers = new Map<string, ReturnType<typeof setTimeout>>();

// ── IPC token helpers ─────────────────────────────────────────────────────────
function generateIpcToken() { return crypto.randomBytes(32).toString('hex'); }

function getTokenFilePath() {
    const uid = typeof (process as any).getuid === 'function' ? (process as any).getuid() : 'token';
    return path.join(os.tmpdir(), `auditlens_ipc_${uid}.key`);
}

function writeIpcToken(token: string) {
    try { fs.writeFileSync(getTokenFilePath(), token, { encoding: 'utf8', mode: 0o600 }); }
    catch (e) { console.error('AuditLens: could not write IPC token', e); }
}

function verifyIpcMessage(raw: string): any | null {
    try {
        const envelope = JSON.parse(raw.trim());
        if (!envelope.payload) return null;
        if (!ipcToken) return envelope.payload;
        const expected = crypto.createHmac('sha256', ipcToken)
            .update(JSON.stringify(envelope.payload)).digest('hex');
        return envelope.sig === expected ? envelope.payload : null;
    } catch { return null; }
}

// ── Config helpers ────────────────────────────────────────────────────────────
function cfg<T>(key: string, def: T): T {
    return vscode.workspace.getConfiguration('auditlens').get<T>(key, def);
}

// ── Activation ────────────────────────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext) {
    console.log('AuditLens activated.');

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = '$(shield) AuditLens';
    statusBarItem.tooltip = 'AuditLens Security Scanner — click to scan';
    statusBarItem.command = 'auditlens.scanFile';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    diagnosticCollection = vscode.languages.createDiagnosticCollection('auditlens');
    context.subscriptions.push(diagnosticCollection);

    ipcToken = generateIpcToken();
    writeIpcToken(ipcToken);

    const SUPPORTED = ['python', 'javascript', 'javascriptreact', 'typescript', 'typescriptreact', 'swift'];

    // ── T2-4: Scan on save ────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(doc => {
            if (cfg('enableOnSave', true) && SUPPORTED.includes(doc.languageId)) {
                runAuditLensScan(doc);
            }
        })
    );

    // ── T2-4: Scan on open (with debounce) ────────────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => {
            if (!cfg('enableOnOpen', true)) return;
            if (!SUPPORTED.includes(doc.languageId)) return;
            const key = doc.uri.toString();
            const existing = openScanTimers.get(key);
            if (existing) clearTimeout(existing);
            const debounce = cfg<number>('scanDebounceMs', 500);
            const timer = setTimeout(() => {
                openScanTimers.delete(key);
                runAuditLensScan(doc);
            }, debounce);
            openScanTimers.set(key, timer);
        })
    );

    // ── IPC server ────────────────────────────────────────────────────────────
    const ipcServer = net.createServer(socket => {
        let buffer = '';
        socket.on('data', data => {
            buffer += data.toString('utf8');
            const lines = buffer.split('\n');
            buffer = lines.pop() ?? '';
            for (const line of lines) {
                if (!line.trim()) continue;
                const msg = verifyIpcMessage(line);
                if (!msg) continue;
                if (msg.type === 'crash_report') handleCrashReport(msg);
            }
        });
        socket.on('error', err => console.error('AuditLens IPC error:', err.message));
    });

    ipcServer.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
            console.warn(`AuditLens: IPC port ${IPC_PORT} in use — crash reporting unavailable.`);
        } else { console.error('AuditLens IPC server error:', err.message); }
    });

    ipcServer.listen(IPC_PORT, 'localhost', () => {
        console.log(`AuditLens IPC server on port ${IPC_PORT}`);
    });

    context.subscriptions.push({
        dispose: () => {
            ipcServer.close();
            try { fs.unlinkSync(getTokenFilePath()); } catch { /* ok */ }
        }
    });

    // ── Commands ──────────────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('auditlens.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) { vscode.window.showErrorMessage('AuditLens: No active editor.'); return; }
            if (!SUPPORTED.includes(editor.document.languageId)) {
                vscode.window.showErrorMessage('AuditLens: Unsupported file type.');
                return;
            }
            runAuditLensScan(editor.document);
        }),

        vscode.commands.registerCommand('auditlens.clearDiagnostics', () => {
            diagnosticCollection.clear();
            statusBarItem.text = '$(shield) AuditLens';
        }),

        vscode.commands.registerCommand('auditlens.runPostMortem', () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor || editor.document.languageId !== 'python') {
                vscode.window.showErrorMessage('AuditLens: Open a Python file to use Post-Mortem.');
                return;
            }
            const currentFile = editor.document.uri.fsPath;
            const pythonPath = vscode.workspace
                .getConfiguration('python').get<string>('defaultInterpreterPath', 'python3');
            const runnerScript = context.asAbsolutePath(
                path.join('..', 'lsp-server', 'auditlens_runner.py')
            );
            if (!fs.existsSync(runnerScript)) {
                vscode.window.showErrorMessage(`AuditLens: Runner not found at ${runnerScript}.`);
                return;
            }
            const terminal = vscode.window.createTerminal('AuditLens Run');
            terminal.show();
            terminal.sendText(`"${pythonPath}" "${runnerScript}" "${currentFile}"`);
        })
    );
}

// ── Crash report handler ──────────────────────────────────────────────────────
function handleCrashReport(message: any) {
    vscode.window.showErrorMessage(
        `AuditLens Post-Mortem: Crash in ${path.basename(message.file)}:${message.line}\n` +
        `${message.exception_type}: ${message.exception_message}`,
        { modal: true }
    );
    const filePath: string = message.file ?? '';
    if (!path.isAbsolute(filePath) || !fs.existsSync(filePath)) return;
    vscode.workspace.openTextDocument(vscode.Uri.file(filePath)).then(doc => {
        vscode.window.showTextDocument(doc).then(editor => {
            const pos = new vscode.Position(Math.max(0, (message.line ?? 1) - 1), 0);
            editor.selection = new vscode.Selection(pos, pos);
            editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        });
    });
}

// ── Scanner ───────────────────────────────────────────────────────────────────
function runAuditLensScan(document: vscode.TextDocument) {
    const filePath = document.uri.fsPath;
    statusBarItem.text = '$(sync~spin) AuditLens: Scanning...';

    // T2-4: read settings from VS Code configuration
    const minSeverity = cfg<string>('minSeverity', 'MEDIUM');
    const enableSCA = cfg<boolean>('enableSCA', false);

    const auditlensPath = fs.existsSync('/opt/homebrew/bin/auditlens')
        ? '/opt/homebrew/bin/auditlens'
        : 'auditlens';

    const sarifPath = path.join(
        os.tmpdir(),
        `auditlens_${crypto.createHash('md5').update(filePath).digest('hex')}.sarif`
    );
    try { fs.unlinkSync(sarifPath); } catch { /* ok */ }

    const scaFlag = enableSCA ? '' : '--no-sca';
    const command = `${auditlensPath} scan "${filePath}" --format sarif --output "${sarifPath}" --severity ${minSeverity} ${scaFlag}`;

    cp.exec(command, { timeout: 30000 }, (error, _stdout, stderr) => {
        if (error && !fs.existsSync(sarifPath)) {
            statusBarItem.text = '$(shield) AuditLens: Error';
            vscode.window.showErrorMessage(`AuditLens: Scan failed. ${stderr || error.message}`);
            return;
        }
        if (!fs.existsSync(sarifPath)) {
            statusBarItem.text = '$(shield) AuditLens';
            return;
        }
        try {
            const sarifData = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
            const count = updateDiagnostics(document, sarifData);
            statusBarItem.text = count > 0
                ? `$(warning) AuditLens: ${count} finding${count !== 1 ? 's' : ''}`
                : '$(pass) AuditLens: Clean';
        } catch (e: any) {
            statusBarItem.text = '$(shield) AuditLens';
            vscode.window.showErrorMessage(`AuditLens: Error parsing SARIF: ${e.message}`);
        } finally {
            try { fs.unlinkSync(sarifPath); } catch { /* ok */ }
        }
    });
}

function updateDiagnostics(document: vscode.TextDocument, sarifData: any): number {
    diagnosticCollection.delete(document.uri);
    const diagnostics: vscode.Diagnostic[] = [];
    const results: any[] = sarifData.runs?.[0]?.results ?? [];

    for (const result of results) {
        const loc = result.locations?.[0]?.physicalLocation;
        if (!loc?.region) continue;
        const line = (loc.region.startLine ?? 1) - 1;
        const safeLineIdx = Math.min(line, document.lineCount - 1);
        const startCol = (loc.region.startColumn ?? 1) - 1;
        const endCol = loc.region.endColumn
            ? loc.region.endColumn - 1
            : document.lineAt(safeLineIdx).text.length;
        const range = new vscode.Range(line, startCol, line, endCol);

        let severity = vscode.DiagnosticSeverity.Warning;
        if (result.level === 'error') severity = vscode.DiagnosticSeverity.Error;
        else if (result.level === 'note') severity = vscode.DiagnosticSeverity.Information;

        const diagnostic = new vscode.Diagnostic(
            range,
            `[${result.ruleId}] ${result.message?.text ?? ''}`,
            severity,
        );
        diagnostic.source = 'AuditLens';
        diagnostic.code = result.ruleId;
        diagnostics.push(diagnostic);
    }
    diagnosticCollection.set(document.uri, diagnostics);
    return diagnostics.length;
}

export function deactivate() {
    diagnosticCollection?.dispose();
    statusBarItem?.dispose();
    for (const t of openScanTimers.values()) clearTimeout(t);
    openScanTimers.clear();
    try { fs.unlinkSync(getTokenFilePath()); } catch { /* ok */ }
}
