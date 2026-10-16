export type RecoveryOutcome = 'connected' | 'retry' | 'blocked';
export type RecoveryReason = 'retry' | 'credentials' | 'ended' | 'identity' | 'changed' | 'removed' | 'manual' | 'signin';

export type ComputerIdentity = {id:string;address:string;port:number;username:string;auth:string;tmux:boolean;fingerprint?:string};
export type ResumeTarget = {host:ComputerIdentity;direct?:boolean;session?:string;sessionRef?:string;window?:{id:string};requestedWindow?:string;needsCredentials?:boolean};

export function savedTabChoice(target:ResumeTarget):{session:string;sessionRef:string;window:string} | undefined {
  const window=target.window?.id || target.requestedWindow;
  if (target.direct || !target.session || !/^[a-f0-9]{64}$/.test(target.sessionRef || '') || !/^@[0-9]+$/.test(window || '')) return;
  return {session:target.session,sessionRef:target.sessionRef!,window:window!};
}

export function sameComputer(a:ComputerIdentity,b:ComputerIdentity):boolean {
  return a.id===b.id && a.address===b.address && a.port===b.port && a.username===b.username && a.auth===b.auth && a.fingerprint===b.fingerprint;
}

export function recoveryFailure(status:number,message:string):RecoveryReason {
  if (status===401) return 'signin';
  if (status===404) return 'removed';
  if (/selected session|selected tab no longer exists|remote shell ended/i.test(message)) return 'ended';
  if (/could not be unlocked|enter the SSH password/i.test(message)) return 'credentials';
  if (/saved server identity|SSH connection refused|fingerprint|identity.*changed/i.test(message)) return 'identity';
  if (/computer changed/i.test(message)) return 'changed';
  if (status===403 || status===400 || status===409 && !/close a terminal/i.test(message)) return 'manual';
  return 'retry';
}

export interface RecoveryClock {
  now():number;
  set(callback:()=>void,delay:number):unknown;
  clear(handle:unknown):void;
}
const browserClock:RecoveryClock = {now:()=>Date.now(),set:(callback,delay)=>setTimeout(callback,delay),clear:handle=>clearTimeout(handle as ReturnType<typeof setTimeout>)};
const delays=[1000,2000,4000,8000,15000,30000];

// One connection attempt at a time, with capped backoff. Hidden pages have no
// retry timers; wake events can retry promptly without creating duplicate work.
export class RecoveryQueue {
  private entries=new Map<string,{failures:number;due:number}>();
  private timer:unknown;
  private running=false;
  private canRun:()=>boolean;
  private attempt:(id:string)=>Promise<RecoveryOutcome>;
  private clock:RecoveryClock;
  constructor(canRun:()=>boolean,attempt:(id:string)=>Promise<RecoveryOutcome>,clock:RecoveryClock=browserClock) { this.canRun=canRun;this.attempt=attempt;this.clock=clock; }
  request(id:string,immediate=false) {
    if (!this.entries.has(id)) this.entries.set(id,{failures:0,due:this.clock.now()+(immediate ? 0 : delays[0])});
    this.schedule();
  }
  forget(id:string) { this.entries.delete(id); this.schedule(); }
  clear() { this.entries.clear(); this.suspend(); }
  suspend() { if (this.timer!==undefined) this.clock.clear(this.timer); this.timer=undefined; }
  wake() { for (const entry of this.entries.values()) { entry.failures=0; entry.due=this.clock.now(); } this.schedule(); }
  private schedule() {
    this.suspend();
    if (this.running || !this.canRun() || !this.entries.size) return;
    const due=Math.min(...[...this.entries.values()].map(entry=>entry.due));
    this.timer=this.clock.set(()=>{this.timer=undefined;void this.run();},Math.max(0,due-this.clock.now()));
  }
  private async run() {
    if (this.running || !this.canRun()) return;
    const next=[...this.entries].sort((a,b)=>a[1].due-b[1].due)[0];
    if (!next || next[1].due>this.clock.now()) { this.schedule(); return; }
    const [id,entry]=next;
    this.running=true;
    let outcome:RecoveryOutcome='retry';
    try { outcome=await this.attempt(id); } catch { /* The adapter exposes any actionable error. */ }
    if (this.entries.get(id)===entry) {
      if (outcome!=='retry') this.entries.delete(id);
      else { entry.failures++; entry.due=this.clock.now()+delays[Math.min(entry.failures,delays.length-1)]; }
    }
    this.running=false;
    this.schedule();
  }
}

// An application-level ping verifies a real round trip: WebSocket.OPEN alone
// cannot establish that a connection survived sleep or a network change.
export class TerminalHeartbeat {
  private pending?:{nonce:string;timer:unknown;promise:Promise<boolean>;finish:(healthy:boolean)=>void};
  private clock:RecoveryClock;
  private nonce:()=>string;
  constructor(clock:RecoveryClock=browserClock,nonce:()=>string=()=>crypto.randomUUID()) { this.clock=clock;this.nonce=nonce; }
  check(send:(nonce:string)=>void):Promise<boolean> {
    if (this.pending) return this.pending.promise;
    let finish!:(healthy:boolean)=>void;
    const promise=new Promise<boolean>(resolve=>finish=resolve);
    const nonce=this.nonce();
    const timer=this.clock.set(()=>this.complete(false),10000);
    this.pending={nonce,timer,promise,finish};
    try { send(nonce); } catch { this.complete(false); }
    return promise;
  }
  accept(nonce:unknown):boolean {
    if (!this.pending || nonce!==this.pending.nonce) return false;
    this.complete(true); return true;
  }
  cancel() { this.complete(false); }
  private complete(healthy:boolean) {
    const pending=this.pending; if (!pending) return;
    this.pending=undefined; this.clock.clear(pending.timer); pending.finish(healthy);
  }
}
