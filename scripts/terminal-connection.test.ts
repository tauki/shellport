import assert from 'node:assert/strict';
import test from 'node:test';
import { TerminalConnection } from '../web/src/terminal-connection.ts';

class Socket { closes=0;close(){this.closes++;} }

test('closing an attached terminal only closes its WebSocket, including after a remote exit',async()=>{
  const requests:string[]=[],socket=new Socket();
  const terminal=new TerminalConnection<Socket>('attached',async id=>{requests.push(id);});
  terminal.setSocket(socket);terminal.markAttached();
  await terminal.close();await terminal.close();
  assert.equal(socket.closes,1);
  assert.deepEqual(requests,[]);
  assert.equal(terminal.socket,undefined);
});

test('closing before WebSocket attachment cancels the pending terminal exactly once',async()=>{
  for (const withSocket of [false,true]) {
    const requests:string[]=[],socket=new Socket();
    const terminal=new TerminalConnection<Socket>('pending',async id=>{requests.push(id);});
    if (withSocket) terminal.setSocket(socket);
    const first=terminal.close(),second=terminal.close();
    assert.equal(first,second);await first;
    assert.deepEqual(requests,['pending']);
    assert.equal(socket.closes,withSocket ? 1 : 0);
  }
});

test('a late socket cannot attach to a cancelled connection or affect its replacement',async()=>{
  const requests:string[]=[],oldSocket=new Socket(),newSocket=new Socket();
  const disconnect=async(id:string)=>{requests.push(id);};
  const oldTerminal=new TerminalConnection<Socket>('old',disconnect);
  await oldTerminal.close();oldTerminal.setSocket(oldSocket);oldTerminal.markAttached();
  const current=new TerminalConnection<Socket>('new',disconnect);
  current.setSocket(newSocket);current.markAttached();
  await oldTerminal.close();
  assert.deepEqual(requests,['old']);assert.equal(oldSocket.closes,1);
  assert.equal(newSocket.closes,0);assert.equal(current.socket,newSocket);
  await current.close();assert.deepEqual(requests,['old']);
});

test('pending cancellation failures are contained and do not repeat requests',async()=>{
  let attempts=0;
  const terminal=new TerminalConnection<Socket>('expired',async()=>{attempts++;throw new Error('offline');});
  await terminal.close();await terminal.close();assert.equal(attempts,1);
});
