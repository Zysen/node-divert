import wd from "../windivert.js";

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
    console.log("Received packet with length:", packet.toString());
    // Return values:
    // - modified packet: to send modified packet
    // - undefined: to send original packet
    // - false: to block/drop the packet
    return packet;
});