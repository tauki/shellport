export interface TerminalSocket { close():void; }

// A live terminal connection is independent of any saved tmux session.
// Once attached, the server owns cleanup when its WebSocket closes. A terminal
// created without an attached socket still needs explicit cancellation.
export class TerminalConnection<Socket extends TerminalSocket> {
  readonly id:string;
  socket?:Socket;
  private attached=false;
  private closing?:Promise<void>;
  private disconnect:(id:string)=>Promise<unknown>;

  constructor(id:string,disconnect:(id:string)=>Promise<unknown>) {
    this.id=id;this.disconnect=disconnect;
  }
  setSocket(socket:Socket) {
    if (this.closing) socket.close();
    else this.socket=socket;
  }
  markAttached() { this.attached=true; }
  close():Promise<void> {
    if (this.closing) return this.closing;
    // Remember attachment even after the socket ends: the server has already
    // cleaned up that connection, so a later tab close must not send DELETE.
    this.closing=this.attached ? Promise.resolve() : Promise.resolve()
      .then(()=>this.disconnect(this.id)).then(()=>{},()=>{});
    const socket=this.socket;this.socket=undefined;socket?.close();
    return this.closing;
  }
}
