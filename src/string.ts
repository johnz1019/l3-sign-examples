declare global {
  interface String {
    hexToBuffer(): Buffer;
  }
}

String.prototype.hexToBuffer = function () {
  const d = String(this);
  return Buffer.from(d.replace('0x', ''), 'hex');
};

export {};
