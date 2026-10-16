const arrows: Record<string,string> = {up:'A',down:'B',right:'C',left:'D'};

export function accessoryInput(key:string, ctrl:boolean, applicationCursorKeys:boolean):string {
  const arrow=arrows[key];
  if (arrow) return ctrl ? `\x1b[1;5${arrow}` : applicationCursorKeys ? `\x1bO${arrow}` : `\x1b[${arrow}`;
  return ({escape:'\x1b',tab:'\t',interrupt:'\x03'} as Record<string,string>)[key] || '';
}

export function controlCharacter(data:string):string | undefined {
  // Apply a one-shot Ctrl to a typed ASCII control chord. Paste, Unicode and
  // existing terminal escape sequences must reach the remote shell unchanged.
  if (data.length !== 1) return;
  if (data === ' ') return '\x00';
  if (data === '?') return '\x7f';
  let code=data.charCodeAt(0);
  if (code >= 97 && code <= 122) code-=32;
  if (code >= 64 && code <= 95) return String.fromCharCode(code & 31);
}
