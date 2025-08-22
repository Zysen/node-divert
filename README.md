# node-windivert: Node.js bindings for WinDivert

## Introduction
This module provides Node.js bindings for the [WinDivert](https://reqrypt.org/windivert.html) project. WinDivert enables packet sniffing, modification, injection and blocking on Windows.

The addon targets modern Node.js releases (20 and later) using the latest [`node-addon-api`](https://github.com/nodejs/node-addon-api) and is compatible with Node.js 24.

## Installation
```bash
npm install windivert
```
Prebuilt binaries for WinDivert are bundled in `bin/<arch>` and are used by default. If no matching binary is available, the install step will compile the addon using [`node-gyp-build`](https://github.com/prebuild/node-gyp-build`).

## Usage
```js
const wd = require('windivert');
wd.listen('tcp.DstPort==80 or tcp.SrcPort==80', (data, inbound) => {
  console.log('HTTP packet with length', data.length);
});
```

### Other examples
```js
// Block a packet
const wd = require('windivert');
wd.listen('tcp.DstPort==80 or tcp.SrcPort==80', (data) => {
  console.log('BLOCKED HTTP packet with length', data.length);
  return false;
});
```

```js
// Modify a packet
require('buffertools').extend();
const wd = require('windivert');
wd.listen('tcp.DstPort==80 or tcp.SrcPort==80', (data) => {
  const d = Buffer.from(data);
  const i = d.indexOf(Buffer.from('BOB'));
  if (i >= 0) {
    d.writeUInt8('S'.charCodeAt(0), i + 0);
    d.writeUInt8('A'.charCodeAt(0), i + 1);
    d.writeUInt8('M'.charCodeAt(0), i + 2);
  }
  return wd.HelperCalcChecksums(d, 0);
});
```

## Building from source
1. Ensure [`node-gyp`](https://github.com/nodejs/node-gyp) is installed and working.
2. Download the WinDivert SDK and extract the required DLL, SYS and LIB files into `bin/<arch>`.
3. Run `npm install` to build. The module will automatically use the custom build from `build/Release` if it exists; otherwise the bundled binaries in `bin` are used.
