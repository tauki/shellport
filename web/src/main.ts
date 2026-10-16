import '@fontsource-variable/manrope';
import '@xterm/xterm/css/xterm.css';
import './style.css';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { accessoryInput, controlCharacter } from './terminal-input';
import { TerminalConnection } from './terminal-connection';
import { RecoveryQueue, TerminalHeartbeat, recoveryFailure, sameComputer, savedTabChoice, type RecoveryOutcome, type RecoveryReason } from './reconnect';
import { canUsePasskeys, credentialJSON, loginOptions, registrationOptions, type PasskeyDirectory, type PasskeyLoginOptions, type PasskeyRecord, type PasskeyRegistrationOptions } from './passkeys';

type Host = {id: string; name: string; address: string; port: number; username: string; auth: 'key'|'password'|'agent'|'local'; tmux: boolean; fingerprint?: string; lastSession?: string; lastWindow?: string;lastSessionRef?:string};
type ShellWindow = {id:string;index:number;name:string;active:boolean};
type TmuxMode = 'independent'|'managed';
type SavedSession = {name:string;windows:number;attached:number;ref:string;mode?:TmuxMode};
type TabChoice = {direct?:boolean;session?:string;sessionRef?:string;window?:string;newWindow?:boolean;create?:boolean;mode?:TmuxMode};
type Tab = {id: string; connection?: TerminalConnection<WebSocket>; host: Host; direct:boolean; session?: string; sessionRef?:string; window?:ShellWindow; requestedWindow?:string; term: Terminal; fit: FitAddon; el: HTMLDivElement; state: 'connecting'|'connected'|'disconnected'; disposed: boolean; epoch:number; connecting:boolean; preflight:boolean; automatic:boolean; needsCredentials:boolean; recoveryReason?:RecoveryReason; recoveryMessage?:string; controller?:AbortController; heartbeat:TerminalHeartbeat; socketReject?:(error:Error)=>void; textSelection?:{view:HTMLPreElement;start:number;disableStdin:boolean}};
type SessionDirectory = {available:boolean;reason?:string;sessions: SavedSession[]; lastSession: string;lastSessionRef?:string; defaultSession: string;defaultMode?:TmuxMode;modes?:TmuxMode[]};
type PrivilegePolicy = 'account'|'restricted';
type LocalPrivileges = {state:'blocked'|'not-blocked'|'unknown'};
type TmuxModeOption = {mode:TmuxMode;configured:boolean;ready:boolean;sessions:number;canEnable:boolean;reason?:string;operatorSetup?:boolean;privileges?:LocalPrivileges;setup?:{serviceManager?:string;startup:string;privilegePolicy?:string;privilegeEffect?:string}};
type TmuxModes = {defaultMode:TmuxMode;localAvailable:boolean;revision:string;modes:TmuxModeOption[];directPrivileges?:LocalPrivileges};
type Me = {authenticated: boolean; passkeysAvailable?:boolean; publicKey?: string; agentAvailable?: boolean; localShellAvailable?: boolean; maxSessions?: number};
type Probe = {fingerprint: string; keyType: string; changed: boolean; previous?: string};
const app = document.querySelector<HTMLDivElement>('#app')!;
const enc = new TextEncoder();
let hosts: Host[] = [], me: Me = {authenticated: false}, tabs: Tab[] = [], active: Tab | undefined, ctrl = false;
let fontSize = Number(localStorage.getItem('shellport.fontSize')) || 14;
const mobile = matchMedia('(max-width: 760px)');
const svg = (path: string) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
const icons = {
  mark: svg('<path d="M15 4h5v16h-5M4 7l5 5-5 5M11 17h3"/>'),
  computer: svg('<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4M7 8l3 3-3 3M13 14h3"/>'),
  plus: svg('<path d="M12 5v14M5 12h14"/>'),
  close: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  arrow: svg('<path d="M5 12h14M13 6l6 6-6 6"/>'),
  settings: svg('<path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>'),
  copy: svg('<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V4H4v12h4"/>'),
  shield: svg('<path d="M12 3l8 3v6c0 4-5 8-8 9-3-1-8-5-8-9V6l8-3zM8 12l3 3 5-6"/>'),
  sessions: svg('<rect x="7" y="7" width="14" height="14" rx="2"/><path d="M17 7V3H3v14h4M10 11l3 3-3 3M15 17h3"/>'),
  trash: svg('<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/>'),
  chevron: svg('<path d="m9 5 7 7-7 7"/>'),
  more: svg('<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'),
  rename: svg('<path d="m15 4 5 5M4 20l4-1 12-12a2 2 0 0 0-3-3L5 16l-1 4z"/>'),
  passkey: svg('<circle cx="8" cy="8" r="4"/><path d="m11 11 9 9 2-2-3-3 2-2-3-3-2 2M7 7h.01"/>'),
};
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

app.innerHTML = `
  <main id="login-view" class="login-view">
    <div class="login-content"><div class="brand-mark large">${icons.mark}</div>
      <h1>Shellport</h1><p class="tagline">Your shell, anywhere.</p>
      <p id="login-error" class="error login-feedback" role="alert"></p>
      <div id="passkey-entry" class="login-passkey"><button id="login-passkey" class="primary passkey-button" aria-label="Sign in with a passkey" title="Sign in with a passkey">${icons.passkey}</button><button id="use-password" class="text-button login-alternative" aria-controls="login-form" aria-expanded="false">Use password instead</button></div>
      <form id="login-form" hidden><label for="app-password">App password</label><input id="app-password" type="password" autocomplete="current-password" required maxlength="72" />
        <button class="primary" type="submit">Open Shellport ${icons.arrow}</button><button id="use-passkey" class="text-button login-alternative" type="button">Use a passkey</button></form>
    </div>
  </main>
  <div id="workspace" class="workspace" hidden>
    <aside id="sidebar"><div id="directory">
      <div class="brand"><span class="brand-mark">${icons.mark}</span><span>Shellport</span></div>
      <div class="directory-heading"><h2>Computers</h2><button id="add-host" class="icon-button" aria-label="Add computer">${icons.plus}</button></div>
      <label class="sr-only" for="host-search">Search computers</label><input id="host-search" class="search" type="search" placeholder="Find a computer…" />
      <div id="host-list" class="host-list"></div>
      <div class="directory-footer"><span class="privacy-mark">${icons.shield} Private workspace</span><button id="workspace-settings" class="text-button">Connection settings ${icons.settings}</button></div>
    </div></aside>
    <main class="working-area">
      <header class="workspace-header"><button id="computers-toggle" class="text-button" aria-label="Computers" title="Computers">${icons.computer}<span>Computers</span></button>
        <div class="heading-group"><h1 id="working-title">Your workspace</h1><span id="working-subtitle">Choose a computer to begin</span></div>
        <button id="session-picker" class="text-button" aria-label="Sessions" title="Sessions" hidden>${icons.sessions}<span>Sessions</span></button>
        <button id="terminal-options" class="icon-button" aria-label="Terminal options">${icons.settings}</button>
      </header>
      <div id="tab-strip" class="tab-strip" hidden><nav id="tabs" class="tabs" aria-label="Open terminals"></nav><button id="new-terminal-tab" class="icon-button" aria-label="New tab in this session" title="New tab" hidden>${icons.plus}</button></div>
      <div id="terminal-area" class="terminal-area">
        <section id="empty" class="empty"><div class="empty-symbol">${icons.mark}</div><h2>A shell, within reach.</h2><p>Pick a computer and make yourself at home.</p><button id="empty-action" class="primary">Add your first computer ${icons.plus}</button><p class="quiet">Built for your phone. Just as useful at your desk.</p></section>
      </div>
      <div id="reconnect-bar" class="reconnect-bar" hidden><span id="reconnect-message" role="status" aria-live="polite"></span><button id="reconnect" class="primary">Reconnect ${icons.arrow}</button></div>
      <div id="selection-bar" class="selection-bar" hidden><span role="status">Select with touch handles or arrows. Ctrl selects by word.</span><button id="done-selecting" class="text-button">Done</button></div>
      <div id="accessory" class="accessory" aria-label="Terminal keyboard" hidden>
        <button data-key="escape">Esc</button><button data-key="tab">Tab</button><button id="ctrl-key" aria-pressed="false">Ctrl</button><button data-key="interrupt">Ctrl C</button><button data-key="up" aria-label="Up arrow">↑</button><button data-key="down" aria-label="Down arrow">↓</button><button data-key="left" aria-label="Left arrow">←</button><button data-key="right" aria-label="Right arrow">→</button><button id="paste">Paste</button><button id="select-text" aria-label="Select terminal text" aria-pressed="false">Select</button><button id="copy">Copy</button>
      </div>
      <footer class="status-bar"><span id="connection-status"><span class="status-dot"></span> Ready when you are</span><span id="terminal-size" hidden></span></footer>
    </main>
  </div>
  <dialog id="computer-sheet" class="computer-sheet"><div class="sheet-top"><span>Computers</span><button id="close-computers" class="icon-button" aria-label="Close computers">${icons.close}</button></div></dialog>
  <dialog id="modal" class="modal" aria-labelledby="modal-title"><div class="modal-header"><h2 id="modal-title"></h2><button id="close-modal" class="icon-button" aria-label="Close dialog">${icons.close}</button></div><div id="modal-content"></div></dialog>
  <div id="toast" class="toast" role="status" hidden></div>`;

const modal = $<HTMLDialogElement>('modal');
const sheet = $<HTMLDialogElement>('computer-sheet');
let modalRevision = 0;
let modalCleanup: (() => void) | undefined;
let modalRestoreTerminalFocus=true;
let selectionQueue:Promise<void> = Promise.resolve();
let toastTimer: ReturnType<typeof setTimeout>;
let signingOut=false;
let authEpoch=0;
let loginEpoch=0,loginBusy=false,loginPreparing=false,enrollAfterPassword=false;
let preparedLogin:PasskeyLoginOptions|undefined;
let loginController:AbortController|undefined;
let loginPreparedUntil=0;
let monitorTimer:ReturnType<typeof setInterval> | undefined;
const recovery=new RecoveryQueue(()=>me.authenticated && !signingOut && !document.hidden,reconnectSelected);
class ApiError extends Error { status:number;code?:string; constructor(status:number,message:string,code?:string) { super(message);this.status=status;this.code=code; } }
function toast(message: string) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 6000); }
async function api<T>(path: string, method = 'GET', body?: unknown, signal?:AbortSignal): Promise<T> {
  const epoch=authEpoch;
  const res = await fetch('/api'+path, {method, credentials:'same-origin', signal, headers: {'Content-Type':'application/json'}, body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await res.json();
  if (!res.ok) { if (res.status === 401 && path !== '/login' && !path.startsWith('/passkeys/login/') && (!['/passkeys/confirm','/password'].includes(path) || data.code==='sign_in_required') && epoch===authEpoch) requireSignIn(); throw new ApiError(res.status,data.error || 'The request failed. Try again.',data.code); }
  return data as T;
}
function errorText(err: unknown) { return err instanceof Error ? err.message : 'The connection failed. Try again.'; }
function showModal(title: string, html: string, restoreTerminalFocus=true) { modalCleanup?.(); modalCleanup=undefined; modalRestoreTerminalFocus=restoreTerminalFocus; modalRevision++; $('modal-title').textContent = title; $('modal-content').innerHTML = html; if (!modal.open) modal.showModal(); $('modal-content').scrollTop=0; }
function closeModal() { const restore=modalRestoreTerminalFocus; modalCleanup?.(); modalCleanup=undefined; modalRevision++; modal.close(); $('modal-content').replaceChildren(); if (restore && !active?.textSelection) active?.term.focus(); }
$('close-modal').onclick = closeModal;
modal.addEventListener('cancel', () => { modalCleanup?.(); modalCleanup=undefined; modalRevision++; $('modal-content').replaceChildren(); });
$('close-computers').onclick = () => sheet.close();
$('computers-toggle').onclick = () => sheet.showModal();
function moveDirectory() { (mobile.matches ? sheet : $('sidebar')).append($('directory')); if (!mobile.matches && sheet.open) sheet.close(); active && fit(active); }
mobile.addEventListener('change', moveDirectory); moveDirectory();
function fit(tab: Tab) { if (tab !== active || tab.disposed) return; try { const size = tab.fit.proposeDimensions(); if (!size || !Number.isFinite(size.cols) || !Number.isFinite(size.rows) || size.cols < 2 || size.rows < 2) return; tab.term.resize(Math.min(size.cols,500),Math.min(size.rows,300)); $('terminal-size').textContent = `${tab.term.cols} × ${tab.term.rows}`; } catch { /* First layout may not have dimensions yet. */ } }
new ResizeObserver(() => active && fit(active)).observe($('terminal-area'));
function viewportPosition() {
  document.documentElement.style.setProperty('--viewport-top',`${window.visualViewport?.offsetTop || 0}px`);
  document.documentElement.style.setProperty('--viewport-left',`${window.visualViewport?.offsetLeft || 0}px`);
}
function viewport() {
  document.documentElement.style.setProperty('--app-height',`${window.visualViewport?.height || window.innerHeight}px`);
  document.documentElement.style.setProperty('--app-width',`${window.visualViewport?.width || window.innerWidth}px`);
  viewportPosition();
  if(active) requestAnimationFrame(()=>{if(active) fit(active);$('tabs').querySelector('.selected')?.scrollIntoView({block:'nearest',inline:'nearest'});});
}
window.visualViewport?.addEventListener('resize',viewport);
window.visualViewport?.addEventListener('scroll',viewportPosition);
window.addEventListener('resize',viewport);viewport();

async function boot() {
  try {
    me = await api<Me>('/me');
    $('login-view').hidden = me.authenticated; $('workspace').hidden = !me.authenticated;
    if (!me.authenticated) { requireSignIn(); return; }
    loginEpoch++;loginController?.abort();preparedLogin=undefined;
    hosts = await api<Host[]>('/hosts');
    for (const tab of tabs) if (tab.recoveryReason==='signin') tab.recoveryReason='retry';
    renderHosts(); renderTabs(); resumeConnections();
  } catch (err) { $('login-error').textContent = errorText(err); }
}
$<HTMLFormElement>('login-form').onsubmit = async event => {
  event.preventDefault();if(loginBusy) return;loginBusy=true;
  const button = $('login-form').querySelector('button')!; button.disabled = true;$<HTMLButtonElement>('use-passkey').disabled=true; $('login-error').textContent = '';
  const field = $<HTMLInputElement>('app-password'); const password = field.value; field.value = '';
  const enroll=enrollAfterPassword;
  try { await api('/login','POST',{password});authEpoch++;enrollAfterPassword=false;await boot();if(enroll && me.authenticated) addPasskey(true); }
  catch(err) { $('login-error').textContent = errorText(err); }
  finally { loginBusy=false;button.disabled=false;$<HTMLButtonElement>('use-passkey').disabled=false; }
};

function passwordLogin(setup=false,message='') {
  loginEpoch++;loginController?.abort();loginPreparing=false;loginBusy=false;preparedLogin=undefined;enrollAfterPassword=setup;
  $('passkey-entry').hidden=true;$<HTMLFormElement>('login-form').hidden=false;$('use-password').setAttribute('aria-expanded','true');$('login-error').textContent=message;
  $<HTMLInputElement>('app-password').focus();
}
function passkeyLoginView() {
  loginEpoch++;loginController?.abort();loginPreparing=false;preparedLogin=undefined;loginBusy=false;enrollAfterPassword=false;
  $('passkey-entry').hidden=false;$<HTMLFormElement>('login-form').hidden=true;$('use-password').setAttribute('aria-expanded','false');
  $<HTMLInputElement>('app-password').value='';$<HTMLButtonElement>('login-passkey').disabled=false;
  void preparePasskeyLogin();
}
async function preparePasskeyLogin() {
  if(me.authenticated || document.hidden || $('passkey-entry').hidden || loginBusy || loginPreparing || loginPreparedUntil>Date.now() && preparedLogin) return;
  if(!me.passkeysAvailable || !canUsePasskeys()) return;
  const epoch=loginEpoch,controller=new AbortController();loginController=controller;loginPreparing=true;
  const button=$<HTMLButtonElement>('login-passkey');button.disabled=true;button.setAttribute('aria-busy','true');
  const timeout=setTimeout(()=>controller.abort(),12000);
  try {
    const data=await api<PasskeyLoginOptions>('/passkeys/login/begin','POST',{},controller.signal);
    if(epoch!==loginEpoch || me.authenticated) return;
    preparedLogin=data;loginPreparedUntil=data.expiresAt ? Date.parse(data.expiresAt) : Date.now()+180000;
  } catch(err) { if(epoch===loginEpoch && !document.hidden) $('login-error').textContent='Could not prepare passkey sign-in. Try again or use your password.'; }
  finally { clearTimeout(timeout);if(epoch===loginEpoch) {loginPreparing=false;button.disabled=false;button.setAttribute('aria-busy','false');} }
}
$('use-password').onclick=()=>{if(!loginBusy) passwordLogin();};
$('use-passkey').onclick=()=>{if(!loginBusy) { $('login-error').textContent='';loginPreparedUntil=0;passkeyLoginView(); }};
$('login-passkey').onclick=async()=>{
  if(loginBusy || loginPreparing) return;
  if(!me.passkeysAvailable || !canUsePasskeys()) { passwordLogin(false,'Passkeys are not available here. Use your password to sign in.');return; }
  if(!preparedLogin || loginPreparedUntil<=Date.now()) { loginPreparedUntil=0;void preparePasskeyLogin();$('login-error').textContent='Preparing sign-in. Tap the passkey button again when ready.';return; }
  if(preparedLogin.needsPassword) { passwordLogin(true,'Sign in with your password to add a passkey.');return; }
  if(!preparedLogin.options) { passwordLogin();return; }
  const options=preparedLogin.options.publicKey,epoch=loginEpoch,controller=new AbortController();loginController=controller;loginBusy=true;
  const button=$<HTMLButtonElement>('login-passkey');button.disabled=true;button.setAttribute('aria-busy','true');$('login-error').textContent='';
  try {
    // Options are prepared before this click so Safari gets a fresh user gesture.
    const credential=await navigator.credentials.get({publicKey:loginOptions(options),signal:controller.signal}) as PublicKeyCredential|null;
    if(epoch!==loginEpoch || controller.signal.aborted) return;
    if(!credential) throw new DOMException('No passkey returned','NotAllowedError');
    await api('/passkeys/login/finish','POST',{credential:credentialJSON(credential)},controller.signal);
    if(epoch!==loginEpoch) return;authEpoch++;await boot();
  } catch(err) {
    if(epoch!==loginEpoch || controller.signal.aborted) return;
    passwordLogin(true,'Passkey sign-in was not completed. Use your password to sign in or add a passkey.');
  } finally { if(epoch===loginEpoch) {loginBusy=false;button.disabled=false;button.setAttribute('aria-busy','false');preparedLogin=undefined;} else if(me.authenticated) loginBusy=false; }
};

function confirmPasskeyManagement(next:()=>void,back:()=>void,message='Sign in again before changing passkeys.') {
  showModal('Confirm your password',`<form id="passkey-confirm-form" class="stack-form"><p class="field-note">${esc(message)}</p><label for="confirm-password">App password</label><input id="confirm-password" type="password" autocomplete="current-password" required maxlength="72"/><p id="passkey-confirm-error" class="error" role="alert"></p><button class="primary" type="submit">Continue ${icons.arrow}</button><button id="passkey-confirm-back" class="text-button" type="button">Cancel</button></form>`,false);
  const revision=modalRevision,controller=new AbortController();modalCleanup=()=>controller.abort();
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  $('passkey-confirm-back').onclick=back;
  $<HTMLFormElement>('passkey-confirm-form').onsubmit=async event=>{
    event.preventDefault();const button=$('passkey-confirm-form').querySelector('button')!;button.disabled=true;
    const password=$<HTMLInputElement>('confirm-password').value;$<HTMLInputElement>('confirm-password').value='';$('passkey-confirm-error').textContent='';
    try { await api('/passkeys/confirm','POST',{password},controller.signal);if(current()) next(); }
    catch(err) {if(current()) {$('passkey-confirm-error').textContent=errorText(err);button.disabled=false;} }
  };
}

function addPasskey(fromLogin=false,initialName='') {
  const back=()=>fromLogin ? closeModal() : settings();
  showModal('Add a passkey',`<form id="add-passkey-form" class="stack-form">
    <p class="field-note">Use your device’s screen lock to sign in.</p>
    <label for="passkey-name">Passkey name <span class="optional-label">(optional)</span></label>
    <input id="passkey-name" placeholder="My passkey" maxlength="80" value="${esc(initialName)}" autocomplete="off"/>
    <p id="add-passkey-status" class="field-note" role="status">Preparing passkey setup…</p>
    <p id="add-passkey-error" class="error" role="alert"></p>
    <button id="add-passkey-submit" class="primary" type="submit" disabled>Add passkey ${icons.passkey}</button>
    <button id="add-passkey-back" class="text-button" type="button">${fromLogin?'Not now':'Cancel'}</button></form>`,false);
  const revision=modalRevision,controller=new AbortController();modalCleanup=()=>controller.abort();
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  let prepared:PasskeyRegistrationOptions|undefined,busy=false;
  const button=$<HTMLButtonElement>('add-passkey-submit');
  $('add-passkey-back').onclick=back;
  const prepare=async()=>{
    if(!canUsePasskeys() || !me.passkeysAvailable) { $('add-passkey-status').textContent='Use a browser that supports passkeys at your HTTPS address.';return; }
    button.disabled=true;button.setAttribute('aria-busy','true');$('add-passkey-status').textContent='Preparing passkey setup…';
    const timeout=setTimeout(()=>controller.abort(),12000);
    try {
      const options=await api<PasskeyRegistrationOptions>('/passkeys/register/begin','POST',{},controller.signal);
      if(!current()) return;prepared=options;button.disabled=false;$('add-passkey-status').textContent='Tap Add passkey to open your device’s prompt.';
    } catch(err) {
      if(!current()) return;
      if(err instanceof ApiError && err.code==='reauth_required') { const name=$<HTMLInputElement>('passkey-name').value;confirmPasskeyManagement(()=>addPasskey(fromLogin,name),back);return; }
      $('add-passkey-status').textContent='';$('add-passkey-error').textContent=controller.signal.aborted?'Setup timed out. Close this dialog and try again.':errorText(err);
    } finally {clearTimeout(timeout);if(current()) button.setAttribute('aria-busy','false');}
  };
  $<HTMLFormElement>('add-passkey-form').onsubmit=async event=>{
    event.preventDefault();if(busy || !prepared || !current()) return;
    if(Date.parse(prepared.expiresAt)<=Date.now()) {prepared=undefined;void prepare();return;}
    const name=$<HTMLInputElement>('passkey-name').value.trim() || 'My passkey';
    if([...name].length>80 || /[\x00-\x1f\x7f-\x9f]/.test(name)) { $('add-passkey-error').textContent='Use a passkey name of up to 80 characters.';return; }
    busy=true;button.disabled=true;button.setAttribute('aria-busy','true');$('add-passkey-error').textContent='';$('add-passkey-status').textContent='Complete the prompt on your device.';
    try {
      // Invoke WebAuthn in this click, before any network await (required by Safari).
      const credential=await navigator.credentials.create({publicKey:registrationOptions(prepared.options.publicKey),signal:controller.signal}) as PublicKeyCredential|null;
      if(!current() || controller.signal.aborted) return;
      if(!credential) throw new DOMException('No passkey returned','NotAllowedError');
      await api('/passkeys/register/finish','POST',{name,credential:credentialJSON(credential)},controller.signal);
      if(current()) {back();toast('Passkey added.');}
    } catch(err) {
      if(!current() || controller.signal.aborted) return;
      if(err instanceof ApiError && err.code==='reauth_required') {confirmPasskeyManagement(()=>addPasskey(fromLogin,name),back);return;}
      $('add-passkey-error').textContent=err instanceof DOMException ? err.name==='InvalidStateError' ? 'This passkey is already registered. Use it to sign in.' : 'Passkey setup was not completed. Try again when you’re ready.' : errorText(err);
      prepared=undefined;busy=false;void prepare();
    } finally {if(current()) {busy=false;button.setAttribute('aria-busy','false');}}
  };
  void prepare();
}

function removePasskey(key:PasskeyRecord) {
  showModal('Remove passkey?',`<div class="stack-form"><p>Remove “${esc(key.name)}” from Shellport?</p>
    <p class="field-note">This device can still sign in with your app password. The saved key may remain in your device’s password manager.</p>
    <p id="remove-passkey-error" class="error" role="alert"></p>
    <button id="remove-passkey-confirm" class="primary destructive">Remove passkey</button>
    <button id="remove-passkey-back" class="text-button">Cancel</button></div>`,false);
  const revision=modalRevision,controller=new AbortController();modalCleanup=()=>controller.abort();
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  $('remove-passkey-back').onclick=settings;
  $('remove-passkey-confirm').onclick=async()=>{
    const button=$<HTMLButtonElement>('remove-passkey-confirm');button.disabled=true;
    try {await api(`/passkeys/${encodeURIComponent(key.id)}`,'DELETE',{confirm:true},controller.signal);if(current()) {settings();toast('Passkey removed.');}}
    catch(err) {
      if(!current()) return;
      if(err instanceof ApiError && err.code==='reauth_required') {confirmPasskeyManagement(()=>removePasskey(key),settings);return;}
      $('remove-passkey-error').textContent=errorText(err);button.disabled=false;
    }
  };
}

async function settingsPasskeys(revision:number) {
  const controller=new AbortController();modalCleanup=()=>controller.abort();
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  try {
    const directory=await api<PasskeyDirectory>('/passkeys','GET',undefined,controller.signal);if(!current()) return;
    $('passkeys-list').replaceChildren();
    if(!directory.passkeys.length) $('passkeys-list').innerHTML='<p class="field-note">No passkeys yet.</p>';
    for(const key of directory.passkeys) {
      const row=document.createElement('div');row.className='passkey-row';const menuID=`passkey-options-${key.id}`;
      row.innerHTML=`<div><strong>${esc(key.name)}</strong><small>${key.availableHere ? key.lastUsedAt ? `Last used ${esc(new Date(key.lastUsedAt).toLocaleDateString())}` : `Added ${esc(new Date(key.createdAt).toLocaleDateString())}` : esc(key.address)}</small></div><button class="icon-button session-more" aria-label="More options for ${esc(key.name)}" aria-haspopup="menu" aria-expanded="false" aria-controls="${menuID}" title="Passkey options">${icons.more}</button><div id="${menuID}" class="session-options" popover="auto" role="menu" aria-label="Options for ${esc(key.name)}"><button class="text-button rename-passkey" role="menuitem" tabindex="-1">${icons.rename} Rename passkey</button><button class="text-button danger remove-passkey" role="menuitem" tabindex="-1">${icons.trash} Remove passkey</button></div>`;
      $('passkeys-list').append(row);
      const hide=bindOptionsMenu(row.querySelector<HTMLButtonElement>('.session-more')!,row.querySelector<HTMLDivElement>('.session-options')!,controller.signal);
      row.querySelector<HTMLButtonElement>('.rename-passkey')!.onclick=()=>{hide();renamePasskey(key);};
      row.querySelector<HTMLButtonElement>('.remove-passkey')!.onclick=()=>{hide();removePasskey(key);};
    }
    const add=$<HTMLButtonElement>('settings-add-passkey');add.disabled=!directory.canAdd || !canUsePasskeys();add.onclick=()=>addPasskey();
    $('passkeys-status').textContent=add.disabled ? 'Use a browser that supports passkeys at your HTTPS address.' : '';
  } catch(err) {if(current()) {$('passkeys-list').replaceChildren();$('passkeys-status').textContent=errorText(err);}}
}

function renamePasskey(key:PasskeyRecord) {
  showModal('Rename passkey',`<form id="rename-passkey-form" class="stack-form"><label for="rename-passkey-name">Passkey name</label><input id="rename-passkey-name" value="${esc(key.name)}" maxlength="80" required autocomplete="off"/><p id="rename-passkey-error" class="error" role="alert"></p><div class="form-actions"><button id="rename-passkey-back" class="text-button" type="button">Cancel</button><button class="primary" type="submit">Save name ${icons.rename}</button></div></form>`,false);
  const revision=modalRevision,controller=new AbortController();modalCleanup=()=>controller.abort();
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  $('rename-passkey-back').onclick=settings;
  $<HTMLFormElement>('rename-passkey-form').onsubmit=async event=>{
    event.preventDefault();const name=$<HTMLInputElement>('rename-passkey-name').value.trim();const button=$('rename-passkey-form').querySelector<HTMLButtonElement>('[type=submit]')!;button.disabled=true;
    try {await api(`/passkeys/${encodeURIComponent(key.id)}`,'PATCH',{name},controller.signal);if(current()) {settings();toast('Passkey renamed.');}}
    catch(err) {if(current()) {$('rename-passkey-error').textContent=errorText(err);button.disabled=false;}}
  };
}

function changePassword() {
  showModal('Change password',`<form id="change-password-form" class="stack-form">
    <p class="field-note">Signs out every device and disconnects terminals. Saved tmux sessions keep running.</p>
    <label for="current-password">Current password</label><input id="current-password" type="password" autocomplete="current-password" required maxlength="72"/>
    <label for="new-password">New password</label><input id="new-password" type="password" autocomplete="new-password" required maxlength="72" aria-describedby="new-password-note"/>
    <p id="new-password-note" class="field-note">Use 12–72 bytes. Most letters, numbers and symbols use one byte.</p>
    <label for="confirm-new-password">Confirm new password</label><input id="confirm-new-password" type="password" autocomplete="new-password" required maxlength="72"/>
    <p id="change-password-error" class="error" role="alert"></p><button class="primary" type="submit">Change password ${icons.passkey}</button><button id="change-password-back" class="text-button" type="button">Cancel</button></form>`,false);
  const revision=modalRevision,controller=new AbortController();modalCleanup=()=>controller.abort();
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  $('change-password-back').onclick=settings;
  $<HTMLFormElement>('change-password-form').onsubmit=async event=>{
    event.preventDefault();const old=$<HTMLInputElement>('current-password'),next=$<HTMLInputElement>('new-password'),confirmation=$<HTMLInputElement>('confirm-new-password');
    const size=new TextEncoder().encode(next.value).length;
    if(size<12 || size>72) {$('change-password-error').textContent='Use a new password between 12 and 72 bytes.';return;}
    if(next.value!==confirmation.value) {$('change-password-error').textContent='The new passwords do not match.';return;}
    const input={currentPassword:old.value,password:next.value,confirmPassword:confirmation.value};old.value='';
    const button=$('change-password-form').querySelector<HTMLButtonElement>('[type=submit]')!;button.disabled=true;button.setAttribute('aria-busy','true');$('change-password-error').textContent='';
    try {await api('/password','POST',input,controller.signal);if(current()) {requireSignIn();toast('Password changed. Sign in again.');}}
    catch(err) {if(current()) {$('change-password-error').textContent=errorText(err);button.disabled=false;button.setAttribute('aria-busy','false');}}
  };
}

function renderHosts() {
  const query = $<HTMLInputElement>('host-search').value.toLowerCase();
  $('host-list').replaceChildren();
  for (const host of hosts.filter(h => `${h.name} ${h.address}`.toLowerCase().includes(query))) {
    const row = document.createElement('div'); row.className = 'host-row';
    row.innerHTML = `<button class="host-connect"><span class="computer-icon">${icons.computer}</span><span class="host-label"><strong>${esc(host.name)}</strong><small>${esc(host.username)}@${esc(host.address)}</small></span></button><button class="host-edit icon-button" aria-label="Edit ${esc(host.name)}">${icons.settings}</button>`;
    row.querySelector<HTMLButtonElement>('.host-connect')!.onclick = () => { if (sheet.open) sheet.close(); void prepareConnection(host); };
    row.querySelector<HTMLButtonElement>('.host-edit')!.onclick = () => { if (sheet.open) sheet.close(); editHost(host); };
    $('host-list').append(row);
  }
  if (!hosts.length) $('host-list').innerHTML = '<p class="directory-empty">Your computers will appear here.<br>Add one to open its shell.</p>';
  else if (!$('host-list').children.length) $('host-list').innerHTML = '<p class="directory-empty">No computers match that search.</p>';
  $('empty-action').innerHTML = hosts.length ? `Choose a computer ${icons.arrow}` : `Add your first computer ${icons.plus}`;
}
$('host-search').oninput = renderHosts;
$('add-host').onclick = () => { if (sheet.open) sheet.close(); editHost(); };
$('empty-action').onclick = () => {
  if (!hosts.length) { editHost(); return; }
  if (mobile.matches) { sheet.showModal(); return; }
  showModal('Choose a computer', '<div id="computer-picker-list" class="host-list computer-picker-list" aria-label="Saved computers"></div>');
  for (const host of hosts) {
    const button=document.createElement('button'); button.className='host-connect';
    button.innerHTML=`<span class="computer-icon">${icons.computer}</span><span class="host-label"><strong>${esc(host.name)}</strong><small>${esc(host.username)}@${esc(host.address)}</small></span>`;
    button.onclick=() => { closeModal(); void prepareConnection(host); };
    $('computer-picker-list').append(button);
  }
};

function editHost(host?: Host) {
  showModal(host ? 'Edit computer' : 'Add a computer', `<form id="host-form" class="stack-form">
    <label for="host-name">Name</label><input id="host-name" name="name" placeholder="My server" value="${esc(host?.name || '')}" required maxlength="80" />
    <div class="form-row"><div><label for="host-address">Hostname or IP address</label><input id="host-address" name="address" placeholder="server.example.com" value="${esc(host?.address || '')}" required spellcheck="false" autocapitalize="none" /></div><div class="port-field"><label for="host-port">Port</label><input id="host-port" name="port" type="number" min="1" max="65535" value="${host?.port || 22}" required inputmode="numeric" /></div></div>
    <label for="host-user">SSH username</label><input id="host-user" name="username" placeholder="username" value="${esc(host?.username || '')}" required spellcheck="false" autocapitalize="none" />
    <label for="host-auth">Connection</label><select id="host-auth" name="auth"><option value="key">SSH with Shellport’s key</option><option value="password">SSH with a password</option>${me.agentAvailable ? '<option value="agent">Server’s SSH agent</option>' : ''}${me.localShellAvailable ? '<option value="local">This Shellport server</option>' : ''}</select>
    <p class="error" id="host-error" role="alert"></p><div class="form-actions">${host ? '<button id="delete-host" type="button" class="danger text-button">Remove computer</button>' : '<span></span>'}<button type="submit" class="primary">Save computer ${icons.arrow}</button></div></form>`);
  $<HTMLSelectElement>('host-auth').value = host?.auth || 'key';
  $('host-auth').onchange = () => { if ($<HTMLSelectElement>('host-auth').value === 'local') $<HTMLInputElement>('host-address').value = '127.0.0.1'; };
  $<HTMLFormElement>('host-form').onsubmit = async event => {
    event.preventDefault(); const form = event.currentTarget as HTMLFormElement; const values = new FormData(form); const button = form.querySelector<HTMLButtonElement>('button[type=submit]')!; button.disabled = true;
    try {
      await api(host ? `/hosts/${host.id}` : '/hosts',host ? 'PUT':'POST', {name:String(values.get('name')), address:String(values.get('address')), port:Number(values.get('port')), username:String(values.get('username')), auth:String(values.get('auth'))});
      hosts = await api<Host[]>('/hosts'); renderHosts(); closeModal();
    } catch(err) { $('host-error').textContent = errorText(err); } finally { button.disabled = false; }
  };
  const del = $('delete-host');
  if (del && host) del.onclick = () => {
    showModal('Remove this computer?', `<p>${esc(host.name)} will leave the directory. Its remote files and tmux sessions stay on the computer.</p><div class="form-actions"><button id="keep-host" class="text-button">Keep computer</button><button id="confirm-remove" class="primary">Remove computer</button></div>`);
    $('keep-host').onclick = closeModal;
    $('confirm-remove').onclick = async () => { try { await api(`/hosts/${host.id}`,'DELETE'); hosts = await api<Host[]>('/hosts'); renderHosts(); closeModal(); } catch(err) { toast(errorText(err)); } };
  };
}

async function prepareConnection(host: Host, reuse?: Tab) {
  if (reuse?.connecting || reuse?.preflight) return;
  if (reuse) { recovery.forget(reuse.id);reuse.recoveryReason=undefined; }
  if (reuse && (!sameComputer(reuse.host,host) || !reuse.direct && !savedTabChoice(reuse))) { await prepareConnection(host);return; }
  if (reuse?.direct && tabs.filter(t => t !== reuse && t.state !== 'disconnected').length >= (me.maxSessions || 4)) { toast('Close a terminal before opening another.'); return; }
  try {
    if (!host.fingerprint && host.auth !== 'local') {
      toast('Checking the computer’s SSH identity…');
      const probe = await api<Probe>(`/hosts/${host.id}/probe`,'POST',{});
      showModal('Verify this computer', `<p>Before connecting to <strong>${esc(host.name)}</strong>, compare this fingerprint with the computer’s SSH host key.</p><div class="fingerprint">${esc(probe.fingerprint)}</div><p class="field-note">${esc(probe.keyType)} · ${esc(host.address)}:${host.port}<br>Trust only an identity you recognize.</p><p id="trust-error" class="error" role="alert"></p><button id="trust-host" class="primary full">Trust and continue ${icons.arrow}</button>`);
      $('trust-host').onclick = async () => { try { await api(`/hosts/${host.id}/trust`,'POST',{fingerprint:probe.fingerprint}); hosts = await api<Host[]>('/hosts'); renderHosts(); closeModal(); await prepareConnection(hosts.find(h=>h.id === host.id)!,reuse); } catch(err) { $('trust-error').textContent = errorText(err); } };
      return;
    }
    if (host.auth === 'password') { requestCredentials(host,reuse,false); return; }
    if (reuse?.needsCredentials && host.auth==='key') { requestCredentials(host,reuse,true);return; }
    await connectOrPick(host,'','',reuse);
  } catch(err) { toast(errorText(err)); }
}
function requestCredentials(host: Host, reuse: Tab|undefined, key: boolean, newWindowSession?:SavedSession) {
  showModal(`Connect to ${host.name}`, `<form id="credential-form" class="stack-form"><p>${esc(host.username)}@${esc(host.address)}</p><label for="ssh-secret">${key ? 'SSH key passphrase' : 'SSH password'}</label><input id="ssh-secret" type="password" autocomplete="off" required /><p class="field-note">Used for this connection only. Shellport does not save it.</p><button type="submit" class="primary">Connect ${icons.arrow}</button></form>`);
  $<HTMLFormElement>('credential-form').onsubmit = event => { event.preventDefault(); const input = $<HTMLInputElement>('ssh-secret'); const value = input.value; input.value=''; closeModal(); if (newWindowSession) void pickSessionTabs(host,newWindowSession,key ? '' : value,key ? value : '',true); else void connectOrPick(host,key ? '' : value,key ? value : '',reuse); };
}
async function connectOrPick(host: Host, password: string, passphrase: string, reuse?: Tab) {
  if (!reuse) await pickSession(host,password,passphrase);
  else await connect(host,password,passphrase,reuse,reuse?.direct ? {direct:true} : {session:reuse?.session,sessionRef:reuse?.sessionRef,window:reuse?.window?.id || reuse?.requestedWindow});
}
function bindOptionsMenu(more:HTMLButtonElement, options:HTMLDivElement, signal:AbortSignal) {
  const hide=() => { if (options.matches(':popover-open')) options.hidePopover(); more.setAttribute('aria-expanded','false'); };
  options.addEventListener('toggle',() => more.setAttribute('aria-expanded',String(options.matches(':popover-open'))));
  const show=(last=false) => {
    more.focus(); options.showPopover(); more.setAttribute('aria-expanded','true');
    const anchor=more.getBoundingClientRect(), menu=options.getBoundingClientRect();
    options.style.left=`${Math.max(8,Math.min(anchor.right-menu.width,innerWidth-menu.width-8))}px`;
    options.style.top=`${anchor.bottom+4+menu.height <= innerHeight-8 ? anchor.bottom+4 : Math.max(8,anchor.top-menu.height-4)}px`;
    const items=options.querySelectorAll<HTMLButtonElement>('[role="menuitem"]');
    items[last ? items.length-1 : 0].focus({preventScroll:true});
  };
  more.setAttribute('popovertarget',options.id);
  more.onclick=event => { event.preventDefault(); if (options.matches(':popover-open')) hide(); else show(); };
  more.onkeydown=event => { if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); if (!options.matches(':popover-open')) show(event.key === 'ArrowUp'); } };
  options.onkeydown=event => {
    if (event.key === 'Escape') { event.preventDefault(); hide(); more.focus(); }
    else if (event.key === 'Tab') { hide(); more.focus(); }
    else if (['ArrowDown','ArrowUp','Home','End'].includes(event.key)) {
      event.preventDefault(); const items=Array.from(options.querySelectorAll<HTMLButtonElement>('[role="menuitem"]'));
      const index=items.indexOf(document.activeElement as HTMLButtonElement);
      items[event.key === 'Home' ? 0 : event.key === 'End' ? items.length-1 : (index+(event.key === 'ArrowUp' ? -1 : 1)+items.length)%items.length].focus();
    }
  };
  modal.addEventListener('scroll',hide,{capture:true,signal});
  window.addEventListener('resize',hide,{signal});
  return hide;
}
function windowLabel(window:ShellWindow) { return `Tab ${window.index+1} · ${window.name}`; }
function windowChoiceRow(host:Host, session:SavedSession, window:ShellWindow, lastWindow:string, credentials:{password:string;passphrase:string}, signal:AbortSignal, open:()=>void) {
  const row=document.createElement('div'); row.className='session-window-row';
  const label=windowLabel(window), existing=findOpenTab(host,session,window.id), optionsID=`tab-options-${crypto.randomUUID()}`;
  row.innerHTML=`<button class="session-window-choice" aria-label="${esc(`${existing ? 'Go to' : 'Open'} ${label}`)}"><span class="session-copy"><strong>${esc(label)}</strong><small>${existing ? 'Already open here' : window.id === lastWindow ? 'Last used tab' : 'Ready to resume'}</small></span><span class="session-action">${existing ? 'Go to tab' : 'Open'} ${icons.arrow}</span></button><button class="icon-button session-more" aria-label="More options for ${esc(label)}" aria-haspopup="menu" aria-expanded="false" aria-controls="${optionsID}" title="Tab options">${icons.more}</button><div id="${optionsID}" class="session-options" popover="auto" role="menu" aria-label="Options for ${esc(label)}"><button class="text-button rename-shell-tab" role="menuitem" tabindex="-1">${icons.rename} Rename tab</button><button class="text-button danger close-shell-tab" role="menuitem" tabindex="-1">${icons.close} Close tab</button></div>`;
  row.querySelector<HTMLButtonElement>('.session-window-choice')!.onclick=open;
  const hide=bindOptionsMenu(row.querySelector<HTMLButtonElement>('.session-more')!,row.querySelector<HTMLDivElement>('.session-options')!,signal);
  row.querySelector<HTMLButtonElement>('.rename-shell-tab')!.onclick=() => { hide(); const {password,passphrase}=credentials; renameShellTab(host,session,window,password,passphrase); };
  row.querySelector<HTMLButtonElement>('.close-shell-tab')!.onclick=() => { hide(); const {password,passphrase}=credentials; confirmCloseShellTab(host,session,window,password,passphrase); };
  return row;
}
async function pickSession(host: Host, password: string, passphrase: string, expandedRef?:string) {
  const credentials = {password,passphrase};
  showModal(`Sessions on ${host.name}`, '<p class="field-note" role="status">Finding sessions…</p>');
  const revision = modalRevision;
  const menuEvents=new AbortController();
  modalCleanup = () => { credentials.password=''; credentials.passphrase=''; menuEvents.abort(); };
  const current = () => modal.open && modalRevision === revision;
  const choose = (name: string, create: boolean, mode?:TmuxMode) => {
    const {password,passphrase} = credentials;
    closeModal();
    void connect(host,password,passphrase,undefined,{session:name,create,...(mode?{mode}:{})});
  };
  const advancedOptions = (modeChoice='') => modeChoice ? `<details class="session-advanced"><summary>Advanced</summary><div class="session-advanced-options">${modeChoice}</div></details>` : '';
  const directAction = (primary=false) => `<div class="direct-shell-option"><button type="button" id="open-direct-shell" class="${primary?'primary full':'text-button'}" aria-describedby="direct-shell-note">Open direct shell ${icons.arrow}</button><p id="direct-shell-note" class="field-note">Ends when you disconnect.</p></div>`;
  const bindDirectAction = () => {
    $('open-direct-shell').onclick = () => {
      const {password,passphrase}=credentials;
      closeModal();
      void connect(host,password,passphrase,undefined,{direct:true});
    };
  };
  const load = async () => {
    if (!current()) return;
    $('modal-content').innerHTML = '<p class="field-note" role="status">Finding sessions…</p>';
    try {
      const data = await api<SessionDirectory>(`/hosts/${host.id}/tmux-sessions`,'POST',credentials);
      if (!current()) return;
      if (data.available === false) {
        $('modal-title').textContent=`Connect to ${host.name}`;
        $('modal-content').innerHTML=`<div class="session-directory"><p class="field-note">Tmux wasn’t found for this account. Install it on this computer to use saved sessions.</p>${directAction(true)}<button id="refresh-sessions" class="text-button">Refresh sessions</button></div>`;
        bindDirectAction();
        $('refresh-sessions').onclick=()=>void load();
        return;
      }
      $('modal-title').textContent=`Sessions on ${host.name}`;
      const preferred = data.lastSession || data.defaultSession;
      const isPreferred=(session:SavedSession)=>data.lastSessionRef ? session.ref===data.lastSessionRef : session.name===preferred;
      data.sessions.sort((a,b) => Number(isPreferred(b)) - Number(isPreferred(a)) || a.name.localeCompare(b.name));
      const ended = data.lastSession && !data.sessions.some(isPreferred);
      let suggestedName:string;
      do { suggestedName=crypto.randomUUID().slice(0,6); } while (data.sessions.some(session => session.name === suggestedName));
      const modeChoice = data.modes && data.modes.length>1 ? `<fieldset class="session-mode-choice" aria-describedby="session-mode-help"><legend>Session lifetime</legend><div class="mode-segments">${(['managed','independent'] as TmuxMode[]).map(mode=>`<label><input type="radio" name="session-mode" value="${mode}" ${mode===data.defaultMode?'checked':''} /><span>${tmuxModeLabel(mode)}</span></label>`).join('')}</div><p id="session-mode-help" class="field-note">Independent sessions keep running when Shellport stops or restarts. Managed sessions end with Shellport. Both keep running when you disconnect.</p></fieldset>` : '';
      $('modal-content').innerHTML = `<div class="session-directory">
        <p class="field-note">Each session keeps its own shell tabs. Closing a terminal leaves its shell running.</p>
        ${ended ? `<p class="session-note">Your previous session “${esc(data.lastSession)}” has ended.</p>` : ''}
        <div class="session-list" aria-label="Available sessions">${data.sessions.length ? '' : '<p class="session-empty">No sessions yet.<br>Create one to start your workspace.</p>'}</div>
        <form id="new-session-form" class="stack-form"><label for="new-session-name">New session name <span class="optional-label">(optional)</span></label><input id="new-session-name" name="session" placeholder="${suggestedName}" maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false" />${advancedOptions(modeChoice)}<p id="session-error" class="error" role="alert"></p><button type="submit" class="primary full">Create and connect ${icons.plus}</button></form>
        ${directAction()}
        <button id="refresh-sessions" class="text-button">Refresh sessions</button></div>`;
      bindDirectAction();
      const list = $('modal-content').querySelector('.session-list')!;
      for (const session of data.sessions) {
        const row = document.createElement('div'); row.className = 'session-row';
        const label = session.name === data.defaultSession ? 'Default session' : session.name;
        const connected = `${session.mode ? `${tmuxModeLabel(session.mode)} · ` : ''}${session.attached ? `Open in ${session.attached} terminal${session.attached === 1 ? '' : 's'}` : 'Ready to resume'}`;
        const panelID=`session-tabs-${list.children.length}`;
        const optionsID=`session-options-${list.children.length}`;
        row.innerHTML = `<div class="session-row-header"><button class="session-disclosure" aria-label="Tabs in ${esc(label)}" aria-expanded="false" aria-controls="${panelID}"><span class="session-chevron">${icons.chevron}</span><span class="session-copy"><strong>${esc(label)}</strong><small>${session.windows} tab${session.windows === 1 ? '' : 's'} · ${connected}</small></span></button><button class="session-resume" aria-label="${esc(`${isPreferred(session) ? 'Continue' : 'Open'} ${label}`)}">${isPreferred(session) ? 'Continue' : 'Open'}</button><button class="icon-button session-more" aria-label="More options for ${esc(label)}" aria-haspopup="menu" aria-expanded="false" aria-controls="${optionsID}" title="Session options">${icons.more}</button></div><div id="${optionsID}" class="session-options" popover="auto" role="menu" aria-label="Options for ${esc(label)}"><button class="text-button rename-session" role="menuitem" tabindex="-1">${icons.rename} Rename session</button><button class="text-button danger delete-session" role="menuitem" tabindex="-1">${icons.trash} Delete session</button></div><div id="${panelID}" class="session-tabs-panel" aria-label="Tabs in ${esc(label)}" hidden></div>`;
        const disclosure=row.querySelector<HTMLButtonElement>('.session-disclosure')!;
        const panel=row.querySelector<HTMLDivElement>('.session-tabs-panel')!;
        const more=row.querySelector<HTMLButtonElement>('.session-more')!;
        const options=row.querySelector<HTMLDivElement>('.session-options')!;
        let loading=false, loaded=false;
        const hideOptions=bindOptionsMenu(more,options,menuEvents.signal);
        const openWindow=(window?:ShellWindow,newWindow=false) => {
          const existing=window && findOpenTab(host,session,window.id);
          const {password,passphrase}=credentials;
          closeModal();
          if (existing) { existing.window=window; selectTab(existing); return; }
          void connect(host,password,passphrase,undefined,{session:session.name,sessionRef:session.ref,window:window?.id,newWindow});
        };
        const loadTabs=async () => {
          if (loading || loaded) return;
          loading=true;
          panel.innerHTML='<p class="session-tab-note" role="status">Finding shell tabs…</p>';
          try {
            const data=await api<{windows:ShellWindow[];lastWindow:string}>(`/hosts/${host.id}/tmux-windows`,'POST',{...credentials,session:session.name,ref:session.ref});
            if (!current() || !row.isConnected) return;
            panel.replaceChildren();
            if (!data.windows.length) panel.innerHTML='<p class="session-tab-note">No shell tabs remain. Create one below.</p>';
            for (const window of data.windows) {
              panel.append(windowChoiceRow(host,session,window,data.lastWindow,credentials,menuEvents.signal,() => openWindow(window)));
            }
            const add=document.createElement('button'); add.className='text-button new-session-tab';
            add.innerHTML=`${icons.plus} New tab`; add.setAttribute('aria-label',`New tab in ${label}`);
            add.onclick=() => openWindow(undefined,true); panel.append(add);
            loaded=true;
          } catch (err) {
            if (!current() || !row.isConnected) return;
            if (errorText(err).includes('could not be unlocked')) { credentialsForPicker(host); return; }
            if (errorText(err).includes('saved server identity')) { identityRecovery(host,undefined,errorText(err)); return; }
            panel.innerHTML=`<p class="error session-tab-note" role="alert">${esc(errorText(err))}</p><button class="text-button retry-session-tabs">Try again</button>`;
            panel.querySelector<HTMLButtonElement>('.retry-session-tabs')!.onclick=() => void loadTabs();
          } finally { loading=false; }
        };
        const expand=() => { hideOptions(); panel.hidden=false; disclosure.setAttribute('aria-expanded','true'); void loadTabs(); };
        disclosure.onclick=() => { if (panel.hidden) expand(); else { panel.hidden=true; disclosure.setAttribute('aria-expanded','false'); } };
        row.querySelector<HTMLButtonElement>('.session-resume')!.onclick = () => {
          const existing = findOpenTab(host,session);
          if (existing) { closeModal(); selectTab(existing); return; }
          const {password,passphrase} = credentials;
          if (session.windows === 1) { closeModal(); void connect(host,password,passphrase,undefined,{session:session.name,sessionRef:session.ref}); }
          else expand();
        };
        row.querySelector<HTMLButtonElement>('.rename-session')!.onclick = () => { hideOptions(); const {password,passphrase} = credentials; renameSession(host,session,label,password,passphrase); };
        row.querySelector<HTMLButtonElement>('.delete-session')!.onclick = () => { hideOptions(); const {password,passphrase} = credentials; confirmDeleteSession(host,session,label,password,passphrase); };
        list.append(row);
        if (session.ref === expandedRef) expand();
      }
      const selectedMode=()=>($('new-session-form').querySelector<HTMLInputElement>('input[name="session-mode"]:checked')?.value as TmuxMode|undefined) || data.defaultMode;
      $<HTMLFormElement>('new-session-form').onsubmit = event => {
        event.preventDefault();
        const name = $<HTMLInputElement>('new-session-name').value.trim() || suggestedName;
        if (name && (!/^[\p{L}\p{N} _-]+$/u.test(name) || name.startsWith('__shellport_view_') || Array.from(name).length > 64)) { $('session-error').textContent = 'Use up to 64 letters, numbers, spaces, hyphens or underscores.'; return; }
        const mode=selectedMode();
        if (data.sessions.some(session => session.name === name && (!mode || session.mode===mode))) { $('session-error').textContent = 'That session already exists in this mode. Open it above or choose another name.'; return; }
        choose(name,true,mode);
      };
      $('refresh-sessions').onclick = () => void load();
    } catch(err) {
      if (!current()) return;
      if (errorText(err).includes('could not be unlocked')) { credentials.password=''; credentials.passphrase=''; credentialsForPicker(host); return; }
      if (errorText(err).includes('saved server identity')) { identityRecovery(host,undefined,errorText(err)); return; }
      $('modal-content').innerHTML = `<p class="error" role="alert">${esc(errorText(err))}</p><button id="retry-sessions" class="primary">Try again ${icons.arrow}</button>${directAction()}`;
      bindDirectAction();
      $('retry-sessions').onclick = () => { if (host.auth === 'password') { closeModal(); prepareConnection(host); } else void load(); };
    }
  };
  await load();
}
function findOpenTab(host: Host, session: SavedSession, window?:string) {
  const matches = tabs.filter(tab => tab.host.id === host.id && tab.host.address === host.address && tab.host.port === host.port && tab.host.username === host.username && tab.sessionRef === session.ref && (!window || (tab.window?.id || tab.requestedWindow) === window));
  return matches.find(tab => tab === active) || matches[matches.length-1];
}
async function pickSessionTabs(host: Host, session: SavedSession, password: string, passphrase: string, create = false) {
  const credentials = {password,passphrase};
  showModal(`Tabs in ${session.name === `shellport-${host.id}` ? 'Default session' : session.name}`, '<p class="field-note" role="status">Finding shell tabs…</p>');
  const revision = modalRevision;
  const menuEvents=new AbortController();
  modalCleanup = () => { credentials.password=''; credentials.passphrase=''; menuEvents.abort(); };
  const current = () => modal.open && modalRevision === revision;
  const open = (window?:ShellWindow,newWindow=false) => {
    const existing = window && findOpenTab(host,session,window.id);
    const {password,passphrase} = credentials;
    closeModal();
    if (existing) { existing.window=window; selectTab(existing); return; }
    void connect(host,password,passphrase,undefined,{session:session.name,sessionRef:session.ref,window:window?.id,newWindow});
  };
  try {
    const data = await api<{windows:ShellWindow[];lastWindow:string}>(`/hosts/${host.id}/tmux-windows`,'POST',{...credentials,session:session.name,ref:session.ref});
    if (!current()) return;
    if (create) { open(undefined,true); return; }
    $('modal-content').innerHTML = `<div class="session-directory"><p class="field-note">Each tab has its own shell. Open an existing tab to resume it from this device.</p><div class="session-list" aria-label="Shell tabs"></div><p id="tab-error" class="error" role="alert"></p><button id="create-shell-tab" class="primary full">New tab ${icons.plus}</button><button id="back-to-sessions" class="text-button">Back to sessions</button></div>`;
    const list = $('modal-content').querySelector('.session-list')!;
    for (const window of data.windows) {
      list.append(windowChoiceRow(host,session,window,data.lastWindow,credentials,menuEvents.signal,() => open(window)));
    }
    $('create-shell-tab').onclick=() => open(undefined,true);
    $('back-to-sessions').onclick=() => { const {password,passphrase} = credentials; void pickSession(host,password,passphrase); };
  } catch (err) {
    if (!current()) return;
    if (errorText(err).includes('could not be unlocked')) { if (create) requestCredentials(host,undefined,true,session); else credentialsForPicker(host); return; }
    $('modal-content').innerHTML=`<p class="error" role="alert">${esc(errorText(err))}</p><button id="back-to-sessions" class="primary">Back to sessions</button>`;
    $('back-to-sessions').onclick=() => { const {password,passphrase} = credentials; void pickSession(host,password,passphrase); };
  }
}
function updateSessionName(hostID:string,ref:string,name:string) {
  tabs.filter(tab => tab.host.id === hostID && tab.sessionRef === ref).forEach(tab => tab.session=name);
  renderTabs();
}
function updateWindowName(hostID:string,id:string,name:string,ref?:string) {
  tabs.filter(tab => tab.host.id === hostID && (!ref || tab.sessionRef===ref) && tab.window?.id === id).forEach(tab => { tab.window!.name=name; });
  renderTabs();
}
function renameShellTab(host:Host, session:SavedSession, window:ShellWindow, password:string, passphrase:string) {
  const credentials={password,passphrase};
  showModal('Rename tab',`<form id="rename-tab-form" class="stack-form"><label for="rename-tab-name">Tab name</label><input id="rename-tab-name" value="${esc(window.name)}" maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false" required /><p class="field-note">The name is saved on ${esc(host.name)} and follows this shell between devices.</p><p id="rename-tab-error" class="error" role="alert"></p><div class="form-actions"><button id="cancel-rename-tab" class="text-button" type="button">Cancel</button><button id="save-tab-name" class="primary" type="submit">Save name ${icons.rename}</button></div></form>`);
  const revision=modalRevision;
  modalCleanup=() => { credentials.password=''; credentials.passphrase=''; };
  const back=() => { const {password,passphrase}=credentials; void pickSession(host,password,passphrase,session.ref); };
  $('cancel-rename-tab').onclick=back;
  $<HTMLFormElement>('rename-tab-form').onsubmit=async event => {
    event.preventDefault();
    const name=$<HTMLInputElement>('rename-tab-name').value.trim();
    if (!name || !/^[\p{L}\p{N} _-]+$/u.test(name) || name.startsWith('__shellport_view_') || Array.from(name).length > 64) { $('rename-tab-error').textContent='Use up to 64 letters, numbers, spaces, hyphens or underscores.'; return; }
    const button=$<HTMLButtonElement>('save-tab-name'); button.disabled=true;
    try {
      const saved=await api<{window:ShellWindow}>(`/hosts/${host.id}/tmux-windows/rename`,'POST',{...credentials,session:session.name,ref:session.ref,window:window.id,name});
      updateWindowName(host.id,saved.window.id,saved.window.name,session.ref);
      toast(`Renamed tab to ${saved.window.name}.`);
      if (modal.open && modalRevision === revision) back();
    } catch (err) { if (modal.open && modalRevision === revision) $('rename-tab-error').textContent=errorText(err); }
    finally { button.disabled=false; }
  };
  $<HTMLInputElement>('rename-tab-name').focus(); $<HTMLInputElement>('rename-tab-name').select();
}
function confirmCloseShellTab(host:Host, session:SavedSession, window:ShellWindow, password:string, passphrase:string) {
  const credentials={password,passphrase};
  showModal(`Close ${window.name}?`,`<p>This closes <strong>${esc(windowLabel(window))}</strong> in <strong>${esc(session.name)}</strong> on <strong>${esc(host.name)}</strong> and disconnects its terminals.</p><p class="field-note">Its shell and running commands stop. If this is the session’s last tab, the session ends too. Tabs linked to other tmux sessions keep running there.</p><p class="error">Unsaved terminal work may be lost. Closing cannot be undone.</p><p id="close-tab-error" class="error" role="alert"></p><div class="form-actions"><button id="keep-shell-tab" class="text-button">Keep tab</button><button id="confirm-close-shell-tab" class="primary destructive">Close tab ${icons.close}</button></div>`);
  const revision=modalRevision;
  modalCleanup=() => { credentials.password=''; credentials.passphrase=''; };
  const back=() => { const {password,passphrase}=credentials; void pickSession(host,password,passphrase,session.ref); };
  $('keep-shell-tab').onclick=back;
  $('confirm-close-shell-tab').onclick=async () => {
    const button=$<HTMLButtonElement>('confirm-close-shell-tab'); button.disabled=true;
    try {
      const saved=await api<{host:Host}>(`/hosts/${host.id}/tmux-windows/close`,'POST',{...credentials,session:session.name,ref:session.ref,window:window.id,confirm:true});
      tabs.filter(tab => tab.host.id === host.id && tab.sessionRef === session.ref && (tab.window?.id || tab.requestedWindow) === window.id).forEach(closeTab);
      hosts=hosts.map(host => host.id === saved.host.id ? saved.host : host); renderHosts();
      toast(`Closed ${window.name} on ${host.name}.`);
      if (modal.open && modalRevision === revision) back();
    } catch (err) { if (modal.open && modalRevision === revision) $('close-tab-error').textContent=errorText(err); }
    finally { button.disabled=false; }
  };
}
function renameSession(host: Host, session: SavedSession, label: string, password: string, passphrase: string) {
  const credentials={password,passphrase};
  showModal('Rename session',`<form id="rename-session-form" class="stack-form"><label for="rename-session-name">Session name</label><input id="rename-session-name" value="${esc(label)}" maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false" required /><p class="field-note">The name changes on ${esc(host.name)}. Its shells keep running.</p><p id="rename-session-error" class="error" role="alert"></p><div class="form-actions"><button id="cancel-rename-session" class="text-button" type="button">Cancel</button><button id="save-session-name" class="primary" type="submit">Save name ${icons.rename}</button></div></form>`);
  const revision=modalRevision;
  modalCleanup=() => { credentials.password=''; credentials.passphrase=''; };
  $('cancel-rename-session').onclick=() => { const {password,passphrase}=credentials; void pickSession(host,password,passphrase); };
  $<HTMLFormElement>('rename-session-form').onsubmit=async event => {
    event.preventDefault();
    const name=$<HTMLInputElement>('rename-session-name').value.trim();
    if (!name || !/^[\p{L}\p{N} _-]+$/u.test(name) || name.startsWith('__shellport_view_') || Array.from(name).length > 64) { $('rename-session-error').textContent='Use up to 64 letters, numbers, spaces, hyphens or underscores.'; return; }
    const button=$<HTMLButtonElement>('save-session-name'); button.disabled=true;
    try {
      const saved=await api<{session:SavedSession;host:Host}>(`/hosts/${host.id}/tmux-sessions/rename`,'POST',{...credentials,session:session.name,ref:session.ref,name});
      hosts=hosts.map(host => host.id === saved.host.id ? saved.host : host);
      updateSessionName(host.id,saved.session.ref,saved.session.name);
      toast(`Renamed session to ${saved.session.name}.`);
      if (modal.open && modalRevision === revision) { const {password,passphrase}=credentials; void pickSession(saved.host,password,passphrase); }
    } catch (err) { if (modal.open && modalRevision === revision) $('rename-session-error').textContent=errorText(err); }
    finally { button.disabled=false; }
  };
  $<HTMLInputElement>('rename-session-name').focus(); $<HTMLInputElement>('rename-session-name').select();
}
function confirmDeleteSession(host: Host, session: SavedSession, label: string, password: string, passphrase: string) {
  const credentials={password,passphrase};
  showModal(`Delete ${label}?`, `<p>This ends the session on <strong>${esc(host.name)}</strong>, closes all ${session.windows} shell tab${session.windows === 1 ? '' : 's'}, and disconnects its terminals on every device.</p><p class="error">Unsaved terminal work may be lost. Deletion cannot be undone.</p><p id="delete-session-error" class="error" role="alert"></p><div class="form-actions"><button id="keep-session" class="text-button">Keep session</button><button id="confirm-delete-session" class="primary destructive">Delete session ${icons.trash}</button></div>`);
  const revision = modalRevision;
  modalCleanup=() => { credentials.password=''; credentials.passphrase=''; };
  $('keep-session').onclick=() => { const {password,passphrase} = credentials; void pickSession(host,password,passphrase); };
  $('confirm-delete-session').onclick=async () => {
    const button=$<HTMLButtonElement>('confirm-delete-session'); button.disabled=true;
    try {
      await api(`/hosts/${host.id}/tmux-sessions/delete`,'POST',{...credentials,session:session.name,ref:session.ref,confirm:true});
      tabs.filter(tab => tab.host.id === host.id && tab.sessionRef === session.ref).forEach(closeTab);
      hosts=await api<Host[]>('/hosts'); renderHosts(); toast(`Deleted ${label} on ${host.name}.`);
      if (modal.open && modalRevision === revision) { const {password,passphrase} = credentials; void pickSession(host,password,passphrase); }
    } catch(err) { if (modal.open && modalRevision === revision) $('delete-session-error').textContent=errorText(err); }
    finally { button.disabled=false; }
  };
}
function credentialsForPicker(host: Host) { requestCredentials(host,undefined,true); }
function sessionLabel(tab: Tab) { return tab.session === `shellport-${tab.host.id}` ? 'Default session' : tab.session; }
function newTab(host: Host, choice:TabChoice): Tab {
  const term = new Terminal({fontFamily:'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',fontSize,cursorBlink:true,screenReaderMode:true,scrollback:3000,theme:{background:'#101315',foreground:'#edf0e9',cursor:'#edbd72',selectionBackground:'#465047',black:'#191d20',brightBlack:'#87928e',green:'#86c4a3',red:'#ffb4a9',yellow:'#edbd72',blue:'#8fbada',cyan:'#87cecb',magenta:'#d8abd1',white:'#edf0e9'}});
  const fitAddon = new FitAddon(); term.loadAddon(fitAddon);
  const el = document.createElement('div'); el.className = 'terminal-instance'; $('terminal-area').append(el); term.open(el);
  const tab: Tab = {id:crypto.randomUUID(),host,direct:!!choice.direct,session:choice.session,sessionRef:choice.sessionRef,requestedWindow:choice.window,term,fit:fitAddon,el,state:'connecting',disposed:false,epoch:0,connecting:false,preflight:false,automatic:false,needsCredentials:host.auth==='password',heartbeat:new TerminalHeartbeat()}; tabs.push(tab);
  term.onData(data => { if (tab.textSelection) return; const chord=ctrl ? controlCharacter(data) : undefined; if (chord !== undefined) { data=chord; setCtrl(false); } send(tab,data); });
  term.onResize(size => { if (size.cols >= 2 && size.cols <= 500 && size.rows >= 2 && size.rows <= 300 && tab.connection?.socket?.readyState === WebSocket.OPEN) tab.connection?.socket.send(JSON.stringify({type:'resize',...size})); });
  selectTab(tab); return tab;
}
async function connect(host: Host, password: string, passphrase: string, reuse?: Tab, choice:TabChoice = {}, automatic=false):Promise<RecoveryOutcome> {
  if (reuse?.disposed || reuse?.connecting) return 'blocked';
  if (!reuse && !choice.create && !choice.newWindow && choice.sessionRef && choice.session) { const existing=findOpenTab(host,{name:choice.session,ref:choice.sessionRef,windows:0,attached:0},choice.window); if (existing) { selectTab(existing); return 'connected'; } }
  if (tabs.filter(t => t !== reuse && t.state !== 'disconnected').length >= (me.maxSessions || 4)) { if (reuse) markDisconnected(reuse,'retry','Close a terminal before resuming this one.');if (!automatic) toast('Close a terminal before opening another.');return 'retry'; }
  const tab = reuse || newTab(host,choice);
  if (!automatic) recovery.forget(tab.id);
  const closing=cancelConnection(tab); const epoch=tab.epoch;
  tab.host=host; tab.state='connecting'; tab.connecting=true;tab.automatic=automatic;tab.recoveryReason=undefined;tab.recoveryMessage=undefined;
  tab.needsCredentials ||= !!password || !!passphrase || host.auth==='password';
  const controller=new AbortController();tab.controller=controller;
  const timeout=setTimeout(()=>controller.abort(),35000);
  if (!automatic) selectTab(tab);renderTabs();
  const current=()=>!tab.disposed && tab.epoch===epoch && me.authenticated;
  try {
    await closing;
    if (!current()) return 'blocked';
    const data = await api<{id:string;session:string;host:Host;tmux:boolean;sessionRef:string;window:ShellWindow}>(`/hosts/${host.id}/connect`,'POST',{password,passphrase,cols:tab.term.cols,rows:tab.term.rows,...choice,direct:tab.direct,remember:!automatic},controller.signal);
    const connection = new TerminalConnection<WebSocket>(data.id,disconnectTerminal);
    if (!current()) { void connection.close();return 'blocked'; }
    tab.connection = connection;
    tab.direct = !data.tmux;
    tab.session = data.session || undefined;
    tab.sessionRef=data.sessionRef || undefined; tab.window=data.window?.id ? data.window : undefined; tab.requestedWindow=undefined;
    hosts = hosts.map(saved => saved.id === host.id ? data.host : saved);
    clearTimeout(timeout);tab.controller=undefined;
    await openTerminalSocket(tab,connection,epoch,automatic);
    return 'connected';
  } catch(err) {
    if (!current()) return 'blocked';
    const message=errorText(err), reason=recoveryFailure(err instanceof ApiError ? err.status : 0,message);
    markDisconnected(tab,reason,reason==='retry' ? undefined : message);
    if (!automatic) {
      if (reason==='credentials' && host.auth==='key' && !passphrase) requestCredentials(host,tab,true);
      else if (reason==='identity') identityRecovery(host,tab,message);
      else if (reason!=='retry') toast(message);
    }
    return tab.recoveryReason==='retry' ? 'retry' : 'blocked';
  } finally {
    clearTimeout(timeout);
    if (tab.epoch===epoch) { tab.connecting=false;tab.controller=undefined;renderTabs(); }
  }
}
function disconnectTerminal(id:string):Promise<unknown> {
  return me.authenticated ? api(`/terminals/${id}`,'DELETE',undefined,AbortSignal.timeout(8000)) : Promise.resolve();
}
// Socket callbacks live outside connect's credential-bearing frame.
function openTerminalSocket(tab:Tab,connection:TerminalConnection<WebSocket>,epoch:number,automatic:boolean):Promise<void> {
  return new Promise((resolve,reject)=>{
    const socket=new WebSocket(`${location.protocol==='https:' ? 'wss:' : 'ws:'}//${location.host}/api/terminals/${connection.id}/terminal`);
    connection.setSocket(socket);socket.binaryType='arraybuffer';let ready=false,settled=false;
    const current=()=>!tab.disposed && tab.epoch===epoch && tab.connection===connection && connection.socket===socket && me.authenticated;
    const timeout=setTimeout(()=>fail(new Error('The terminal connection timed out.')),10000);
    const fail=(error:Error)=>{clearTimeout(timeout);if (!settled) { settled=true;tab.socketReject=undefined;reject(error); } void connection.close();};
    tab.socketReject=fail;
    socket.onopen=()=>{
      connection.markAttached();
      clearTimeout(timeout);
      if (!current()) { fail(new Error('Connection canceled.'));return; }
      socket.send(JSON.stringify({type:'resize',cols:tab.term.cols,rows:tab.term.rows}));
      void tab.heartbeat.check(nonce=>socket.send(JSON.stringify({type:'ping',nonce}))).then(healthy=>{
        if (!current()) return;
        if (!healthy) { fail(new Error('The terminal connection timed out.'));return; }
        ready=true;settled=true;tab.socketReject=undefined;tab.state='connected';tab.recoveryReason=undefined;tab.recoveryMessage=undefined;
        recovery.forget(tab.id);renderTabs();rememberSelection(tab);resolve();
        if (!automatic && tab===active && !document.hidden && !modal.open && !tab.textSelection) tab.term.focus();
      });
    };
    socket.onmessage=event=>{
      if (!current()) return;
      if (event.data instanceof ArrayBuffer) { tab.term.write(new Uint8Array(event.data));return; }
      try {
        const message=JSON.parse(String(event.data));
        if (message.type==='pong') tab.heartbeat.accept(message.nonce);
        else if (message.type==='session-renamed' && typeof message.session==='string' && tab.sessionRef) updateSessionName(tab.host.id,tab.sessionRef,message.session);
        else if (message.type==='tab-renamed' && typeof message.window==='string' && typeof message.name==='string') updateWindowName(tab.host.id,message.window,message.name,tab.sessionRef);
        else if (message.type==='exit') markDisconnected(tab,'ended',typeof message.message==='string' ? message.message : 'This shell ended. Choose another saved tab.');
      } catch { /* Metadata is never written into the terminal. */ }
    };
    socket.onclose=()=>{
      if (!current()) return;
      if (!ready) fail(new Error('The terminal connection closed.'));
      else markDisconnected(tab);
    };
    socket.onerror=()=>{if (current()) { if (!ready) fail(new Error('The terminal connection interrupted.'));else markDisconnected(tab); }};
  });
}
function cancelConnection(tab:Tab):Promise<void> {
  tab.epoch++;tab.controller?.abort();tab.controller=undefined;
  const reject=tab.socketReject;tab.socketReject=undefined;
  const connection=tab.connection;tab.connection=undefined;
  reject?.(new Error('Connection canceled.'));tab.heartbeat.cancel();
  tab.connecting=false;tab.preflight=false;
  return connection?.close() || Promise.resolve();
}
function markDisconnected(tab:Tab,reason:RecoveryReason='retry',message?:string) {
  if (tab.disposed) return;
  cancelConnection(tab);tab.state='disconnected';tab.automatic=false;
  if (reason==='retry' && tab.needsCredentials) reason='credentials';
  if (reason==='retry' && !savedTabChoice(tab)) reason='manual';
  tab.recoveryReason=reason;tab.recoveryMessage=message;renderTabs();
  if (reason==='retry' && tab===active) recovery.request(tab.id);
  else recovery.forget(tab.id);
}
async function reconnectSelected(id:string):Promise<RecoveryOutcome> {
  const tab=tabs.find(t=>t.id===id);
  if (!tab || tab!==active || tab.disposed || document.hidden || !me.authenticated || tab.connecting || tab.preflight) return 'blocked';
  const choice=savedTabChoice(tab);
  if (!choice || tab.needsCredentials || tab.recoveryReason && tab.recoveryReason!=='retry') return 'blocked';
  const closing=cancelConnection(tab);const epoch=tab.epoch;
  tab.preflight=true;tab.automatic=true;tab.state='connecting';renderTabs();
  const controller=new AbortController();tab.controller=controller;
  const timeout=setTimeout(()=>controller.abort(),8000);
  const current=()=>!tab.disposed && tab.epoch===epoch && active===tab && !document.hidden && me.authenticated;
  try {
    await closing;
    if (!current()) return 'blocked';
    const saved=await api<Host[]>('/hosts','GET',undefined,controller.signal);
    if (!current()) return 'blocked';
    hosts=saved;renderHosts();
    const host=saved.find(h=>h.id===tab.host.id);
    if (!host) { markDisconnected(tab,'removed');return 'blocked'; }
    if (!sameComputer(tab.host,host)) { markDisconnected(tab,'changed');return 'blocked'; }
    clearTimeout(timeout);tab.controller=undefined;tab.preflight=false;
    return await connect(host,'','',tab,choice,true);
  } catch(err) {
    if (!current()) return 'blocked';
    const reason=recoveryFailure(err instanceof ApiError ? err.status : 0,errorText(err));
    markDisconnected(tab,reason,reason==='retry' ? undefined : errorText(err));
    return reason==='retry' ? 'retry' : 'blocked';
  } finally { clearTimeout(timeout);if (tab.epoch===epoch) { tab.preflight=false;tab.controller=undefined;renderTabs(); } }
}
function requireSignIn() {
  authEpoch++;
  me.authenticated=false;recovery.clear();clearInterval(monitorTimer);monitorTimer=undefined;
  for (const tab of tabs) { cancelConnection(tab);tab.term.blur();tab.state='disconnected';if (!tab.recoveryReason || tab.recoveryReason==='retry') tab.recoveryReason='signin'; }
  if (modal.open) { modalRestoreTerminalFocus=false;closeModal(); }
  if (sheet.open) sheet.close();
  $('workspace').hidden=true;$('login-view').hidden=false;
  passkeyLoginView();
  if (tabs.length) $('login-error').textContent='Sign in again to resume your saved tab.';
}
function probeConnection(tab:Tab) {
  if (document.hidden || !me.authenticated || tab!==active || tab.state!=='connected') return;
  const socket=tab.connection?.socket,epoch=tab.epoch,heartbeat=tab.heartbeat;
  if (socket?.readyState!==WebSocket.OPEN) { markDisconnected(tab);return; }
  void heartbeat.check(nonce=>socket.send(JSON.stringify({type:'ping',nonce}))).then(healthy=>{
    if (!healthy && !document.hidden && me.authenticated && !tab.disposed && tab.epoch===epoch && tab.connection?.socket===socket && tab.heartbeat===heartbeat) markDisconnected(tab);
  });
}
function resumeConnections() {
  if (document.hidden || !me.authenticated || signingOut) return;
  if (!monitorTimer) monitorTimer=setInterval(()=>active && probeConnection(active),20000);
  if (!active) return;
  if (active.state==='connected') probeConnection(active);
  else if (active.state==='disconnected' && (!active.recoveryReason || active.recoveryReason==='retry')) {
    if (active.needsCredentials || !savedTabChoice(active)) markDisconnected(active);
    else { recovery.request(active.id,true);recovery.wake(); }
  }
}
function pauseConnections() {
  recovery.suspend();clearInterval(monitorTimer);monitorTimer=undefined;
  for (const tab of tabs) {
    if (tab.automatic && (tab.connecting || tab.preflight)) { recovery.forget(tab.id);markDisconnected(tab); }
    else if (tab.state==='connected') { tab.heartbeat.cancel();tab.heartbeat=new TerminalHeartbeat(); }
    tab.term.blur();
  }
}
function identityRecovery(host: Host, tab: Tab|undefined, message: string) {
  showModal('Check this connection', `<p>${esc(message)}</p><p>The saved identity is <span class="inline-code">${esc(host.fingerprint || '')}</span>. Verify any change on the remote computer before replacing it.</p><p id="identity-error" class="error" role="alert"></p><button id="check-identity" class="primary">Check current identity</button>`);
  $('check-identity').onclick = async () => { try {
    const probe = await api<Probe>(`/hosts/${host.id}/probe`,'POST',{});
    if (!probe.changed) { $('identity-error').textContent = 'The identity matches. Check the username, authorized key or SSH authentication policy.'; return; }
    showModal('Server identity changed', `<p class="error">${esc(host.name)} is presenting a different SSH host key.</p><p>Compare the new fingerprint on the computer before trusting it.</p><div class="fingerprint">${esc(probe.fingerprint)}</div><p class="field-note">Previous: ${esc(probe.previous || '')}</p><button id="replace-identity" class="primary">I verified this new identity</button>`);
    $('replace-identity').onclick = async () => { try { await api(`/hosts/${host.id}/trust`,'POST',{fingerprint:probe.fingerprint}); hosts = await api<Host[]>('/hosts'); closeModal(); renderHosts(); void prepareConnection(hosts.find(h=>h.id===host.id)!,tab); } catch(err) { toast(errorText(err)); } };
  } catch(err) { $('identity-error').textContent = errorText(err); } };
}
function send(tab: Tab|undefined, data: string) { if (tab?.state==='connected' && tab.connection?.socket?.readyState === WebSocket.OPEN) tab.connection?.socket.send(enc.encode(data)); }
function rememberSelection(tab:Tab) {
  if (tab.state!=='connected' || !tab.connection || !tab.session) return;
  const connection=tab.connection;
  selectionQueue=selectionQueue.then(async()=>{
    if (active!==tab || tab.disposed || tab.state!=='connected' || tab.connection!==connection || !me.authenticated) return;
    try { const saved=await api<Host>(`/terminals/${connection.id}/select`,'POST',{});hosts=hosts.map(host=>host.id===saved.id ? saved : host); }
    catch { /* A concurrent detach does not interrupt local tab focus. */ }
  });
}
function selectTab(tab:Tab) {
  if (tab.disposed) return;
  if (active && active!==tab) {
    stopSelecting(active);recovery.forget(active.id);
    if (active.automatic && (active.connecting || active.preflight)) markDisconnected(active);
    recovery.forget(active.id);
  }
  active=tab;tabs.forEach(t=>t.el.hidden=t!==tab);$('empty').hidden=true;
  requestAnimationFrame(()=>{if (active!==tab || tab.disposed || !me.authenticated || document.hidden) return;fit(tab);if (!tab.textSelection && tab.state==='connected' && !modal.open) tab.term.focus();});
  renderTabs();rememberSelection(tab);resumeConnections();
}
function renderTabs() {
  const nav = $('tabs'); nav.replaceChildren(); $('tab-strip').hidden = !tabs.length;
  for (const tab of tabs) {
    const item = document.createElement('div'); item.className = 'session-tab' + (tab === active ? ' selected':'');
    const title = tab.direct ? `Direct shell · ${tab.host.name}` : tab.session ? `${tab.window ? `${windowLabel(tab.window)} · ` : ''}${sessionLabel(tab)} · ${tab.host.name}` : tab.host.name;
    item.innerHTML = `<button class="select-tab" aria-current="${tab === active ? 'page':'false'}" title="${esc(title)}"><span class="status-dot ${tab.state}"></span><span class="tab-name">${esc(title)}</span></button><button class="close-tab icon-button" aria-label="${tab.direct?'Close':'Detach'} ${esc(title)} terminal" title="${tab.direct?'Close terminal; stop shell':'Detach terminal; keep shell running'}">${icons.close}</button>`;
    item.querySelector<HTMLButtonElement>('.select-tab')!.onclick = ()=>selectTab(tab); item.querySelector<HTMLButtonElement>('.close-tab')!.onclick=()=>closeTab(tab); nav.append(item);
  }
  nav.querySelector('.selected')?.scrollIntoView({block:'nearest',inline:'nearest'});
  $('empty').hidden = !!active; $('accessory').hidden = !active; $('reconnect-bar').hidden = !active || active.state==='connected' || active.state==='connecting' && !active.automatic;
  const selecting=!!active?.textSelection;
  for (const tab of tabs) tab.term.options.disableStdin=tab.state!=='connected' || !!tab.textSelection;
  $('selection-bar').hidden=!selecting; $('select-text').setAttribute('aria-pressed',String(selecting));
  $<HTMLButtonElement>('paste').disabled=selecting || active?.state!=='connected';
  document.querySelectorAll<HTMLButtonElement>('[data-key="tab"],[data-key="interrupt"]').forEach(button=>button.disabled=selecting || active?.state!=='connected');
  $('session-picker').hidden = !active;
  $('new-terminal-tab').hidden = !active?.sessionRef || !!active.direct;
  $('working-title').textContent = active?.host.name || 'Your workspace'; $('working-subtitle').textContent = active ? `${active.session ? `${sessionLabel(active)} · ${active.window ? `${windowLabel(active.window)} · ` : ''}` : ''}${active.host.auth === 'local' ? `${active.host.username} · Shellport server` : `${active.host.username}@${active.host.address}`}` : 'Choose a computer to begin';
  $('connection-status').innerHTML = active ? `<span class="status-dot ${active.state}"></span>${active.state === 'connected' ? (active.direct ? 'Connected · direct shell':'Connected · tmux session') : active.state === 'connecting' ? active.automatic ? 'Reconnecting…' : 'Connecting…' : active.recoveryReason==='retry' ? 'Waiting to reconnect' : 'Disconnected'}` : '<span class="status-dot"></span>Ready when you are';
  const terminalSize=$('terminal-size');terminalSize.hidden=!active;terminalSize.textContent=active ? `${active.term.cols} × ${active.term.rows}` : '';
  const reason=active?.recoveryReason;
  const messages:Record<RecoveryReason,string>={retry:navigator.onLine ? 'Connection lost. Retrying automatically…' : 'You’re offline. We’ll retry when the connection returns.',credentials:'Enter your SSH password or key passphrase to resume.',ended:active?.direct?'This shell ended. Reconnect to open a new shell.':'This shell ended. Choose another saved tab.',identity:'Check the computer’s SSH identity before reconnecting.',changed:'This computer’s connection settings changed. Choose a session again.',removed:'This computer was removed. Choose another computer.',manual:active?.direct ? 'Reconnect to open a new shell.' : 'Reconnect or choose a saved session.',signin:active?.direct?'Sign in again to open a new shell.':'Sign in again to resume.'};
  $('reconnect-message').textContent=active?.state==='connecting' ? 'Reconnecting to your saved tab…' : active?.recoveryMessage || messages[reason || 'manual'];
  const reconnect=$<HTMLButtonElement>('reconnect');reconnect.disabled=!!active && (active.connecting || active.preflight);
  reconnect.innerHTML=`${reason==='ended' ? active?.direct?'Open new shell':'Choose session' : reason==='changed' ? 'Choose session' : reason==='removed' ? 'Choose computer' : reason==='credentials' ? 'Enter credentials' : reason==='identity' ? 'Check connection' : 'Reconnect now'} ${icons.arrow}`;
}
$('new-terminal-tab').onclick=() => {
  if (!active?.session || !active.sessionRef) return;
  const host=active.host, session={name:active.session,ref:active.sessionRef,windows:0,attached:0};
  if (host.auth === 'password') requestCredentials(host,undefined,false,session);
  else void pickSessionTabs(host,session,'','',true);
};
function closeTab(tab: Tab) {
  stopSelecting(tab);
  tab.disposed=true;recovery.forget(tab.id);void cancelConnection(tab); tab.term.dispose(); tab.el.remove(); tabs=tabs.filter(t=>t!==tab);
  if (active === tab) { active=undefined; if (tabs.length) selectTab(tabs[tabs.length-1]); } renderTabs();
}
$('reconnect').onclick = () => {
  const tab=active;if (!tab) return;
  const host=hosts.find(h=>h.id===tab.host.id);
  if (!host || tab.recoveryReason==='removed') { $('empty-action').click();return; }
  if (tab.recoveryReason==='ended' && !tab.direct || tab.recoveryReason==='changed') { void prepareConnection(host);return; }
  if (tab.recoveryReason==='identity') { identityRecovery(host,tab,tab.recoveryMessage || 'Verify this computer before reconnecting.');return; }
  void prepareConnection(host,tab);
};
$('session-picker').onclick = () => active && void prepareConnection(hosts.find(h=>h.id === active!.host.id) || active.host);
function setCtrl(value: boolean) { ctrl=value; $('ctrl-key').setAttribute('aria-pressed',String(value)); }
$('ctrl-key').onpointerdown = e => e.preventDefault(); $('ctrl-key').onclick=()=>setCtrl(!ctrl);
document.querySelectorAll<HTMLButtonElement>('[data-key]').forEach(button=>{button.onpointerdown=e=>e.preventDefault(); button.onclick=()=>{if (!active) return; const key=button.dataset.key!; if (active.textSelection) { if (key === 'escape') { stopSelecting(active); renderTabs(); } else extendTextSelection(active,key); return; } send(active,accessoryInput(key,ctrl,active.term.modes.applicationCursorKeysMode));};});
function stopSelecting(tab:Tab) {
  const state=tab.textSelection; if (!state) return;
  const selection=getSelection();
  if (selection?.anchorNode && state.view.contains(selection.anchorNode)) selection.removeAllRanges();
  state.view.remove(); tab.el.classList.remove('selecting-text'); tab.term.options.disableStdin=tab.state!=='connected'; tab.textSelection=undefined; setCtrl(false);
}
function startSelecting(tab:Tab) {
  if (tab.disposed || tab.textSelection) return;
  const buffer=tab.term.buffer.active;
  let text='', start=0;
  for (let row=0;row<buffer.length;row++) {
    const line=buffer.getLine(row); if (!line) continue;
    if (row && !line.isWrapped) text+='\n';
    if (row === buffer.viewportY) start=text.length;
    text+=line.translateToString(!buffer.getLine(row+1)?.isWrapped);
  }
  text=text.trimEnd();
  if (!text) { toast('There’s no terminal text to select yet.'); return; }
  const view=document.createElement('pre'); view.className='terminal-text-selection'; view.tabIndex=0;
  view.setAttribute('role','region'); view.setAttribute('aria-label','Selectable terminal text'); view.textContent=text;
  view.style.fontSize=`${fontSize}px`;
  view.onkeydown=event=>{if (event.key === 'Escape') { event.preventDefault(); stopSelecting(tab); renderTabs(); } else { const key=({ArrowUp:'up',ArrowDown:'down',ArrowLeft:'left',ArrowRight:'right'} as Record<string,string>)[event.key]; if (key) { event.preventDefault(); extendTextSelection(tab,key,event.ctrlKey || ctrl); } }};
  tab.textSelection={view,start:Math.min(start,text.length),disableStdin:!!tab.term.options.disableStdin};
  tab.term.blur(); tab.term.options.disableStdin=true; tab.el.classList.add('selecting-text'); tab.el.append(view); setCtrl(false); renderTabs();
  // Start at the same visible output while retaining earlier scrollback for copy.
  const range=document.createRange(); range.setStart(view.firstChild!,tab.textSelection.start); range.collapse(true);
  const rect=range.getBoundingClientRect(), bounds=view.getBoundingClientRect();
  if (rect.height) view.scrollTop=Math.max(0,rect.top-bounds.top-8);
}
function extendTextSelection(tab:Tab,key:string,byWord=ctrl) {
  if (!['up','down','left','right'].includes(key) || !tab.textSelection) return;
  const {view,start}=tab.textSelection, selection=getSelection(); if (!selection) return;
  if (!selection.anchorNode || !selection.focusNode || !view.contains(selection.anchorNode) || !view.contains(selection.focusNode)) {
    const range=document.createRange(); range.setStart(view.firstChild!,start); range.collapse(true); selection.removeAllRanges(); selection.addRange(range);
  }
  selection.modify('extend',key === 'left' || key === 'up' ? 'backward' : 'forward',key === 'up' || key === 'down' ? 'line' : byWord ? 'word' : 'character');
  // Native document selection can cross a non-editable pre's boundary. Keep
  // both endpoints in this one text node so repeated arrows never select UI.
  const text=view.firstChild!;
  const anchor=selection.anchorNode === text ? selection.anchorOffset : selection.anchorOffset ? text.textContent!.length : 0;
  const focus=selection.focusNode === text ? selection.focusOffset : key === 'left' || key === 'up' ? 0 : text.textContent!.length;
  selection.setBaseAndExtent(text,anchor,text,focus);
  if (selection.focusNode) {
    const range=document.createRange(); range.setStart(selection.focusNode,selection.focusOffset); range.collapse(true);
    const rect=range.getBoundingClientRect(), bounds=view.getBoundingClientRect();
    if (rect.top < bounds.top) view.scrollTop+=rect.top-bounds.top-8;
    else if (rect.bottom > bounds.bottom) view.scrollTop+=rect.bottom-bounds.bottom+8;
  }
}
$('select-text').onpointerdown=e=>e.preventDefault();
$('select-text').onclick=()=>{if (!active) return; if (active.textSelection) { stopSelecting(active); renderTabs(); } else startSelecting(active);};
$('done-selecting').onclick=()=>{if (active) { stopSelecting(active); renderTabs(); }};
$('copy').onpointerdown=e=>e.preventDefault();
$('copy').onclick=async()=>{
  const tab=active; if (!tab) return;
  const selection=getSelection(), view=tab.textSelection?.view;
  const value=view ? selection?.anchorNode && selection.focusNode && view.contains(selection.anchorNode) && view.contains(selection.focusNode) ? selection.toString() : '' : tab.term.getSelection();
  if (!value) { startSelecting(tab); return; }
  try { await navigator.clipboard.writeText(value); toast('Selection copied.'); } catch { showModal('Copy selection',`<label for="copy-value">Select and copy this text</label><textarea id="copy-value" readonly>${esc(value)}</textarea><button id="done-copying" class="text-button">Done</button>`,false); $('done-copying').onclick=closeModal; }
};
$('paste').onclick=async()=>{
  const tab=active, revision=modalRevision;
  const ready=()=>!!tab && tab === active && !tab.disposed && !tab.textSelection && tab.state==='connected';
  if (!ready()) return;
  try {
    const value=await navigator.clipboard.readText();
    if (!ready() || modal.open || modalRevision !== revision) return;
    tab!.term.paste(value); tab!.term.focus();
  } catch {
    if (!ready() || modal.open || modalRevision !== revision) return;
    showModal('Paste into terminal','<form id="paste-form" class="stack-form"><label for="paste-value">Text to paste</label><textarea id="paste-value" required></textarea><button class="primary" type="submit">Paste</button></form>');
    $<HTMLFormElement>('paste-form').onsubmit=e=>{e.preventDefault(); if (!ready()) { toast('The terminal changed. Choose it again before pasting.'); return; } const value=$<HTMLTextAreaElement>('paste-value').value; closeModal(); tab!.term.paste(value);};
  }
};
function tmuxModeLabel(mode:TmuxMode) { return mode==='managed' ? 'Managed' : 'Independent'; }
function tmuxModeDescription(mode:TmuxMode) { return mode==='managed' ? 'Shellport ends these sessions when it stops or restarts.' : 'These sessions keep running when Shellport stops or restarts.'; }

function modalRequest(timeout:number) {
  const controller=new AbortController(),previous=modalCleanup,timer=setTimeout(()=>controller.abort(),timeout);
  modalCleanup=()=>{previous?.();clearTimeout(timer);controller.abort();};
  return controller;
}

function privilegeLabel(value?:LocalPrivileges) {
  return value?.state==='blocked' ? 'Blocked by process policy' : value?.state==='not-blocked' ? 'Not blocked by this flag' : 'Unknown';
}

function localPrivilegeDetails(data:TmuxModes) {
  return `<div class="local-privileges"><h4>Privilege elevation</h4><dl><div><dt>Direct shells</dt><dd>${privilegeLabel(data.directPrivileges)}</dd></div>${data.modes.filter(option=>option.configured).map(option=>`<div><dt>${tmuxModeLabel(option.mode)} tmux</dt><dd>${privilegeLabel(option.privileges)}</dd></div>`).join('')}</dl><p class="field-note">Checks Linux’s no-new-privileges flag. Other OS rules still apply to sudo. Existing shells may have different restrictions.</p>${data.directPrivileges?.state==='blocked' || data.modes.some(option=>option.configured && option.privileges?.state==='blocked') ? '<p class="field-note">To change restrictions, review the service that starts the affected shells.</p>' : ''}</div>`;
}

async function saveTmuxMode(data:TmuxModes,option:TmuxModeOption,privilegePolicy?:PrivilegePolicy) {
  const revision=modalRevision,controller=modalRequest(60000);
  const current=()=>modal.open && modalRevision===revision && me.authenticated;
  const button=$<HTMLButtonElement>('save-tmux-default');button.disabled=true;button.setAttribute('aria-busy','true');$('tmux-settings-error').textContent='';
  try {
    await api('/tmux-modes','POST',{mode:option.mode,revision:data.revision,confirm:true,...(privilegePolicy?{privilegePolicy}:{})},controller.signal);
    if(current()) {settings();toast(`New sessions default to ${tmuxModeLabel(option.mode).toLowerCase()}. Existing sessions keep running.`);}
  } catch(err) {
    if(!current()) return;
    if(err instanceof ApiError && err.code==='reauth_required') {confirmPasskeyManagement(()=>confirmTmuxMode(data,option,privilegePolicy),settings,'Sign in again before changing local session settings.');return;}
    $('tmux-settings-error').textContent=errorText(err);button.disabled=false;
  } finally {button.removeAttribute('aria-busy');}
}

function confirmTmuxMode(data:TmuxModes,option:TmuxModeOption,policy?:PrivilegePolicy) {
  const configurable=!option.configured && option.mode==='independent' && option.setup?.serviceManager==='systemd user service';
  const selected=policy || (option.setup?.privilegePolicy==='restricted'?'restricted':'account');
  const policyFields=configurable ? `<label for="tmux-privilege-policy">New service privileges</label><select id="tmux-privilege-policy" aria-describedby="tmux-privilege-description"><option value="account" ${selected==='account'?'selected':''}>Use account permissions</option><option value="restricted" ${selected==='restricted'?'selected':''}>Block privilege elevation</option></select><p id="tmux-privilege-description" class="field-note"></p>` : option.setup?.privilegeEffect ? `<p class="field-note">${esc(option.setup.privilegeEffect)}</p>` : '';
  showModal(`${option.configured?'Use':'Enable'} ${tmuxModeLabel(option.mode).toLowerCase()} sessions`, `<div class="stack-form"><p>${tmuxModeDescription(option.mode)}</p>${!option.configured ? `<p class="field-note">${option.mode==='independent' ? 'This creates a separate tmux user service on this computer.' : 'This starts a private tmux server owned by Shellport.'}</p>${option.mode==='independent' && option.setup ? `<p class="field-note">${option.setup.serviceManager==='launchd user agent' ? 'Starts when you sign in to this computer.' : 'Starts with your user services. Starting before login may need additional setup.'}</p>` : ''}` : ''}${policyFields}<p class="field-note">This becomes the default for new sessions. Existing sessions keep their mode and stay running. SSH sessions on other computers are unchanged.</p><p id="tmux-settings-error" class="error" role="alert"></p><div class="form-actions"><button id="cancel-tmux-default" class="text-button">Cancel</button><button id="save-tmux-default" class="primary">${option.configured?'Save default':'Enable and set default'}</button></div></div>`,false);
  const select=configurable?$<HTMLSelectElement>('tmux-privilege-policy'):undefined;
  if(select) {
    const describe=()=>{$('tmux-privilege-description').textContent=select.value==='restricted'?'Blocks programs such as sudo from gaining privileges in this new service.':'Sudo follows this account’s permissions and other OS rules. This does not grant additional permissions.';};
    select.onchange=describe;describe();
  }
  $('cancel-tmux-default').onclick=settings;$('save-tmux-default').onclick=()=>void saveTmuxMode(data,option,select?.value as PrivilegePolicy|undefined);
}

async function settingsTmux(revision:number) {
  const controller=modalRequest(30000),current=()=>modal.open && modalRevision===revision;
  try {
    const data=await api<TmuxModes>('/tmux-modes','GET',undefined,controller.signal);if(!current()) return;
    const target=$('settings-tmux');
    if(!data.localAvailable) {target.innerHTML='<p class="field-note">Local terminals are disabled by the server operator. SSH sessions use tmux on their remote computer.</p>';return;}
    target.innerHTML=`<label for="tmux-default-mode">Default for new sessions</label><select id="tmux-default-mode">${data.modes.map(option=>`<option value="${option.mode}" ${option.mode===data.defaultMode?'selected':''} ${!option.canEnable?'disabled':''}>${tmuxModeLabel(option.mode)}${!option.canEnable?' (unavailable)':''}</option>`).join('')}</select><p id="tmux-mode-description" class="field-note">${tmuxModeDescription(data.defaultMode)}</p><p class="field-note">Existing sessions keep their mode. New tabs inherit their session’s mode.</p><div class="tmux-mode-counts">${data.modes.filter(option=>option.configured).map(option=>`<p class="field-note">${tmuxModeLabel(option.mode)} · ${option.sessions} session${option.sessions===1?'':'s'}${option.operatorSetup?' · operator setup':''}${!option.ready?' · unavailable':''}</p>`).join('')}</div>${data.modes.filter(option=>option.reason).map(option=>`<p class="field-note">${tmuxModeLabel(option.mode)}: ${esc(option.reason!)}</p>`).join('')}<p id="tmux-settings-error" class="error" role="alert"></p><button id="save-tmux-default" class="text-button" disabled>Save default</button>${localPrivilegeDetails(data)}`;
    const select=$<HTMLSelectElement>('tmux-default-mode'),button=$<HTMLButtonElement>('save-tmux-default');
    select.onchange=()=>{const mode=select.value as TmuxMode;$('tmux-mode-description').textContent=tmuxModeDescription(mode);button.disabled=mode===data.defaultMode;};
    button.onclick=()=>{const option=data.modes.find(option=>option.mode===select.value)!;if(!option.canEnable)return;if(option.configured) void saveTmuxMode(data,option);else confirmTmuxMode(data,option);};
  } catch(err) {if(current()) $('settings-tmux').innerHTML=`<p class="error" role="alert">${esc(errorText(err))}</p><button id="retry-tmux-settings" class="text-button">Try again</button>`;if(current()) $('retry-tmux-settings').onclick=()=>void settingsTmux(revision);}
}

function settings() {
  showModal('Workspace settings', `<div class="stack-form"><label for="font-size">Terminal text size</label><select id="font-size">${[12,14,16,18,20].map(n=>`<option value="${n}" ${fontSize===n?'selected':''}>${n} px</option>`).join('')}</select><h3>Local sessions</h3><div id="settings-tmux" class="tmux-settings-fields" aria-live="polite"><p class="field-note">Loading session modes…</p></div><h3>Passkeys</h3><div id="passkeys-list" aria-live="polite"><p class="field-note">Loading passkeys…</p></div><button id="settings-add-passkey" class="text-button" disabled>${icons.plus} Add passkey</button><p id="passkeys-status" class="error" role="alert"></p><h3>Password</h3><button id="settings-change-password" class="text-button">${icons.passkey} Change password</button><h3>Shellport’s public SSH key</h3><p class="field-note">Authorize this public key on computers that use key authentication. The private key stays on your Shellport server.</p>${me.publicKey ? `<textarea id="public-key" readonly>${esc(me.publicKey)}</textarea><button id="copy-key" class="text-button">${icons.copy} Copy public key</button>` : '<p>The server key is encrypted or unavailable. Ask its operator for the public key.</p>'}<h3>Use Shellport on your phone</h3><p class="field-note">Open your HTTPS address in your phone’s browser and add it to the Home Screen. On iPhone, use Safari’s Share menu. Your phone needs a network connection that can reach the Shellport server.</p><button id="sign-out" class="danger text-button">Sign out of this device</button></div>`,false);
  void settingsPasskeys(modalRevision);
  void settingsTmux(modalRevision);
  $('settings-change-password').onclick=changePassword;
  $('font-size').onchange=e=>{fontSize=Number((e.target as HTMLSelectElement).value); localStorage.setItem('shellport.fontSize',String(fontSize)); tabs.forEach(t=>t.term.options.fontSize=fontSize); active&&fit(active);};
  const copy=$('copy-key'); if (copy) copy.onclick=async()=>{try { await navigator.clipboard.writeText(me.publicKey!); toast('Public key copied.'); } catch { $<HTMLTextAreaElement>('public-key').select(); } };
  $('sign-out').onclick=async()=>{
    signingOut=true;recovery.clear();pauseConnections();
    try { await api('/logout','POST',{});me.authenticated=false;for (const tab of [...tabs]) closeTab(tab);hosts=[];requireSignIn();$('login-error').textContent=''; }
    catch(err) { toast(errorText(err)); }
    finally { signingOut=false;resumeConnections(); }
  };
}
$('workspace-settings').onclick=settings; $('terminal-options').onclick=settings;
window.addEventListener('offline',()=>{for (const tab of tabs) if (tab.state==='connected' || tab.automatic && tab.state==='connecting') markDisconnected(tab);});
window.addEventListener('online',()=>{resumeConnections();void preparePasskeyLogin();});
document.addEventListener('visibilitychange',()=>{if(document.hidden) {pauseConnections();if(!me.authenticated && loginPreparing) loginController?.abort();} else {resumeConnections();void preparePasskeyLogin();}});
window.addEventListener('pageshow',resumeConnections);
window.addEventListener('focus',()=>{resumeConnections();void preparePasskeyLogin();});
window.addEventListener('pagehide',()=>{pauseConnections();for (const tab of tabs) if (tab.state==='connected') markDisconnected(tab);});
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(()=>{});
void boot();
