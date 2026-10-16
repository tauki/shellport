import assert from 'node:assert/strict';
import test from 'node:test';
import { accessoryInput, controlCharacter } from '../web/src/terminal-input.ts';

test('Ctrl arrows use modified terminal sequences in normal and application cursor modes',()=>{
  for (const application of [false,true]) {
    assert.equal(accessoryInput('left',true,application),'\x1b[1;5D');
    assert.equal(accessoryInput('up',true,application),'\x1b[1;5A');
  }
  assert.equal(accessoryInput('up',false,false),'\x1b[A');
  assert.equal(accessoryInput('up',false,true),'\x1bOA');
  assert.equal(accessoryInput('down',false,true),'\x1bOB');
  assert.equal(accessoryInput('right',false,true),'\x1bOC');
  assert.equal(accessoryInput('left',false,true),'\x1bOD');
});

test('typed Ctrl characters do not corrupt paste, existing escape sequences or Unicode',()=>{
  assert.equal(controlCharacter('c'),'\x03');
  assert.equal(controlCharacter('C'),'\x03');
  assert.equal(controlCharacter('['),'\x1b');
  assert.equal(controlCharacter(' '),'\x00');
  assert.equal(controlCharacter('?'),'\x7f');
  for (const input of ['é','ß','ı','界','🙂','\x1b[1;5A','\x03','\r','hello','1']) assert.equal(controlCharacter(input),undefined);
});
