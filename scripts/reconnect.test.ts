import assert from 'node:assert/strict';
import test from 'node:test';
import { RecoveryQueue, TerminalHeartbeat, recoveryFailure, sameComputer, savedTabChoice, type RecoveryClock, type RecoveryOutcome } from '../web/src/reconnect.ts';

class Clock implements RecoveryClock {
  time=0;next=0;timers=new Map<number,{at:number;callback:()=>void}>();
  now(){return this.time;}
  set(callback:()=>void,delay:number){const id=++this.next;this.timers.set(id,{at:this.time+delay,callback});return id;}
  clear(handle:unknown){this.timers.delete(handle as number);}
  async advance(milliseconds:number){
    const end=this.time+milliseconds;
    for (;;) {
      await Promise.resolve();await Promise.resolve();
      const next=[...this.timers].filter(([,timer])=>timer.at<=end).sort((a,b)=>a[1].at-b[1].at)[0];
      if (!next) break;
      this.time=next[1].at;this.timers.delete(next[0]);next[1].callback();
      await Promise.resolve();await Promise.resolve();
    }
    this.time=end;await Promise.resolve();await Promise.resolve();
  }
}

test('recovery backs off, caps its rate and resumes promptly after hiding',async()=>{
  const clock=new Clock(), attempts:number[]=[];let visible=true;
  const queue=new RecoveryQueue(()=>visible,async()=>{attempts.push(clock.time);return 'retry';},clock);
  queue.request('tab');await clock.advance(31000);
  assert.deepEqual(attempts,[1000,3000,7000,15000,30000]);
  await clock.advance(60000);assert.deepEqual(attempts.slice(-2),[60000,90000]);
  visible=false;queue.suspend();assert.equal(clock.timers.size,0);
  await clock.advance(300000);assert.equal(attempts.length,7);
  visible=true;const resumedAt=clock.time;queue.wake();await clock.advance(0);assert.equal(attempts.at(-1),resumedAt);
  queue.clear();assert.equal(clock.timers.size,0);
});

test('repeated wake events never duplicate in-flight work, and forgetting a tab cancels retries',async()=>{
  const clock=new Clock();let finish!:(outcome:RecoveryOutcome)=>void;let attempts=0;
  const queue=new RecoveryQueue(()=>true,()=>{attempts++;return new Promise(resolve=>finish=resolve);},clock);
  queue.request('tab',true);await clock.advance(0);
  for(let i=0;i<5;i++){queue.request('tab',true);queue.wake();await clock.advance(0);}
  assert.equal(attempts,1);
  queue.forget('tab');finish('retry');await clock.advance(60000);
  assert.equal(attempts,1);assert.equal(clock.timers.size,0);
});

test('background connection attempts run serially and actionable failures stop retries',async()=>{
  const clock=new Clock(),started:string[]=[];let finish!:(outcome:RecoveryOutcome)=>void;
  const queue=new RecoveryQueue(()=>true,id=>{started.push(id);return new Promise(resolve=>finish=resolve);},clock);
  queue.request('one',true);queue.request('two',true);await clock.advance(0);assert.deepEqual(started,['one']);
  finish('blocked');await clock.advance(0);assert.deepEqual(started,['one','two']);
  finish('connected');await clock.advance(60000);assert.equal(clock.timers.size,0);
});

test('heartbeat verifies a matching pong, shares pending checks and rejects stale responses',async()=>{
  const clock=new Clock();let nonce=0;const sent:string[]=[];
  const heartbeat=new TerminalHeartbeat(clock,()=>String(++nonce));
  const first=heartbeat.check(value=>sent.push(value));
  assert.equal(heartbeat.check(value=>sent.push(value)),first);assert.deepEqual(sent,['1']);
  assert.equal(heartbeat.accept('other'),false);assert.equal(heartbeat.accept('1'),true);assert.equal(await first,true);
  const second=heartbeat.check(value=>sent.push(value));assert.equal(heartbeat.accept('1'),false);
  await clock.advance(10000);assert.equal(await second,false);assert.equal(clock.timers.size,0);
  const cancelled=heartbeat.check(()=>{});heartbeat.cancel();assert.equal(await cancelled,false);assert.equal(clock.timers.size,0);
});

test('resume requires the exact saved session and window; changed destinations and human decisions stay blocked',()=>{
  const host={id:'computer',address:'server.example.com',port:22,username:'operator',auth:'key',tmux:true,fingerprint:'verified'};
  const selected={host,session:'work',sessionRef:'a'.repeat(64),window:{id:'@3'}};
  assert.deepEqual(savedTabChoice(selected),{session:'work',sessionRef:'a'.repeat(64),window:'@3'});
  assert.deepEqual(savedTabChoice({...selected,host:{...host,tmux:false}}),savedTabChoice(selected));
  assert.equal(savedTabChoice({...selected,direct:true}),undefined);
  assert.equal(savedTabChoice({...selected,sessionRef:undefined}),undefined);
  assert.equal(savedTabChoice({...selected,window:undefined}),undefined);
  assert.equal(sameComputer(host,{...host,address:'other.example.com'}),false);
  assert.equal(sameComputer(host,{...host,fingerprint:'changed'}),false);
  assert.equal(sameComputer(host,{...host}),true);
  assert.equal(sameComputer(host,{...host,tmux:false}),true);
  assert.equal(recoveryFailure(401,'Sign in'), 'signin');
  assert.equal(recoveryFailure(409,'The selected tab no longer exists.'),'ended');
  assert.equal(recoveryFailure(502,'SSH key could not be unlocked'),'credentials');
  assert.equal(recoveryFailure(502,'SSH connection refused'),'identity');
  assert.equal(recoveryFailure(403,'Permission denied'),'manual');
  assert.equal(recoveryFailure(502,'could not reach this computer'),'retry');
  assert.equal(recoveryFailure(409,'Close a terminal before opening another.'),'retry');
});
