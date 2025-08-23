# node-windivert: NodeJS bindings for WinDivert

## Introduction
node-windivert provides NodeJS bindings for the WinDivert project, enabling packet sniffing, modification, injection, and blocking capabilities on Windows systems. WinDivert is a powerful packet capture and modification tool that operates at the Windows Network Stack level.

For more information about WinDivert, visit: https://reqrypt.org/windivert.html
Original WinDivert documentation: https://github.com/basil00/Divert/blob/master/README

## Usage
Basic installation and usage:
```javascript
// Install via npm
npm install windivert

// Basic usage example
const wd = require("windivert");

// Create WinDivert instance with filter
const handle = await wd.createWindivert(
    "tcp.DstPort==80 or tcp.SrcPort==80", // Filter string
    wd.LAYERS.NETWORK,                     // Network layer
    wd.FLAGS.DEFAULT                       // Default flags
);

// Open the handle to start capturing
handle.open();

// Add packet receiver
wd.addReceiveListener(handle, (packet, addr) => {
    console.log("Received packet with length:", packet.length);
    // Return values:
    // - modified packet: to send modified packet
    // - undefined: to send original packet
    // - false: to block/drop the packet
    return packet; 
});

// When done, close the handle
// handle.close();
```

## Other Examples

### Blocking Packets
```javascript
const wd = require("windivert");

// Create WinDivert instance for blocking
const handle = await wd.createWindivert(
    "tcp.DstPort==80 or tcp.SrcPort==80",
    wd.LAYERS.NETWORK,
    wd.FLAGS.DEFAULT  // You can use DEFAULT flag for selective blocking
);

// Open the handle
handle.open();

// Add packet receiver that selectively blocks packets
wd.addReceiveListener(handle, (packet, addr) => {
    // You can implement your blocking logic here
    // Example: Block packets larger than 1000 bytes
    if (packet.length > 1000) {
        console.log("Blocking large packet:", packet.length);
        return false; // Return false to block/drop this packet
    }
    
    // Example: Block packets based on content
    if (packet.includes(Buffer.from("BLOCK_ME"))) {
        console.log("Blocking packet containing BLOCK_ME");
        return false; // Return false to block/drop this packet
    }
    
    // Example: Let other packets pass through
    console.log("Allowing packet:", packet.length);
    return undefined; // Return undefined to let the packet pass
});

// When done, close the handle
// handle.close();

// Alternative: Block all packets using FLAGS.DROP
const blockAllHandle = await wd.createWindivert(
    "tcp.DstPort==80 or tcp.SrcPort==80",
    wd.LAYERS.NETWORK,
    wd.FLAGS.DROP // Use DROP flag to block all matching packets
);
blockAllHandle.open();
```

### Modifying Packets
```javascript
const wd = require("windivert");

// Create WinDivert instance
const handle = await wd.createWindivert(
    "tcp.DstPort==80 or tcp.SrcPort==80",
    wd.LAYERS.NETWORK,
    wd.FLAGS.DEFAULT
);

// Open the handle
handle.open();

// Add packet receiver that modifies packets
wd.addReceiveListener(handle, (packet, addr) => {
    // Create a copy of the packet
    const modifiedPacket = Buffer.from(packet);
    
    // Modify the packet as needed
    const searchStr = Buffer.from("BOB");
    const replaceStr = Buffer.from("SAM");
    
    const index = modifiedPacket.indexOf(searchStr);
    if (index >= 0) {
        replaceStr.copy(modifiedPacket, index);
    }
    
    return modifiedPacket;
});

// When done, close the handle
// handle.close();
```

### DPI Circumvention Example
See `examples/goodbyeDPI.js` for a comprehensive example of Deep Packet Inspection circumvention implementation.

## Building

### Prerequisites
1. Ensure node-gyp is installed and properly configured
   - Follow installation instructions at: https://github.com/nodejs/node-gyp

### Build Steps
1. Download WinDivert-2.2.2-A.zip from https://reqrypt.org/windivert.html
2. Extract the contents into the bin directory
3. Run the following commands:
```bash
node-gyp clean
node-gyp configure
node-gyp build
```

### Development Commands
```bash
npm run test         # Run goodbyeDPI example
npm run build:dev    # Build in debug mode
npm run build        # Build in release mode
npm run rebuild:dev  # Clean and build in debug mode
npm run rebuild      # Clean and build in release mode
npm run clean        # Clean build files
```

Note: The module will automatically use the custom-built binary from `build/Release` if it exists, instead of the precompiled binaries in `./bin`.
	