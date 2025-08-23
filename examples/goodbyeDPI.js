var wd = require("../windivert.js");
class Filter {
    static #instance;
    #ipIdTemplate
    #maxPayloadSizeTemplate
    #noLocalIPv4Dst
    #noLocalIPv4Src
    #noLocalIPv6Dst
    #noLocalIPv6Src
    #filterStringTemplate
    #passiveFilterStringTemplate
    constructor(parameters) {
        if (Filter.#instance) {
            throw new Error("Singleton instance already exists. Please use getInstance().");
        }

        this.#ipIdTemplate = `#IPID#`;

        this.#maxPayloadSizeTemplate = `#MAXPAYLOADSIZE#`;

        this.#noLocalIPv4Dst = `((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and (ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))`;

        this.#noLocalIPv4Src = `((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and (ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and (ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and (ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and (ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))`;

        this.#noLocalIPv6Dst = `((ipv6.DstAddr > ::1) and (ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and (ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and (ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and (ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0))`;

        this.#noLocalIPv6Src = `((ipv6.SrcAddr > ::1) and (ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and (ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and (ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and (ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0))`;

        this.#filterStringTemplate = `(tcp and !impostor and !loopback ${this.#maxPayloadSizeTemplate} and (((inbound and (((ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) ${this.#ipIdTemplate}) and tcp.SrcPort == 80 and tcp.Ack) or ((tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn))) and (${this.#noLocalIPv4Src} or ${this.#noLocalIPv6Src})) or (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack and (${this.#noLocalIPv4Dst} or ${this.#noLocalIPv6Dst}))))`;

        this.#passiveFilterStringTemplate = `inbound and ip and tcp and !impostor and !loopback and (true ${this.#ipIdTemplate}) and (tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and ${this.#noLocalIPv4Src}`;

        this.quicBlockPassiveFilter = `outbound and !impostor and !loopback and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01`;

        Filter.#instance = this;
    }
    static getInstance() {
        if (!Filter.#instance) {
            Filter.#instance = new Filter();
        }
        return Filter.#instance;
    }
    generateFilters(ipID, maxPayloadSize = 1200) {
        this.filter = this.#filterStringTemplate;
        this.passiveFilter = this.#passiveFilterStringTemplate;
        if (ipID && typeof ipID === 'number' && ipID >= 0 && ipID <= 65535) {
            this.ipID = ipID;
            this.#addIpIdStr(ipID);
        } else if (ipID !== undefined && ipID !== null) {
            console.warn("Invalid ipID provided.  Must be a number between 0 and 65535. Ignoring.");
        }
        if (maxPayloadSize && typeof maxPayloadSize === 'number' && maxPayloadSize >= 0) {
            this.maxPayloadSize = maxPayloadSize;
            this.#addMaxPayloadSizeStr(maxPayloadSize);
        } else if (maxPayloadSize !== undefined && maxPayloadSize !== null) {
            console.warn("Invalid maxPayloadSize provided.  Must be a number greater than or equal to 0. Ignoring.");
        }
        this.#finalizeFilterStrings();
    }

    addFilterStr(proto, port) {
        const udp = ` or(udp and !impostor and!loopback and (udp.SrcPort == ${port} or udp.DstPort == ${port}))`;
        const tcp = ` or(tcp and !impostor and !loopback ${this.#maxPayloadSizeTemplate} and (tcp.SrcPort == ${port} or tcp.DstPort == ${port}))`;
        if (proto === 'IPPROTO_UDP') {
            this.filter += udp;
        } else {
            this.filter += tcp;
        }
        if (this.maxPayloadSize !== undefined && this.maxPayloadSize !== null) {
            this.#addMaxPayloadSizeStr(this.maxPayloadSize);
        }
        this.#finalizeFilterStrings();
    }
    #addIpIdStr(id) {
        const ipId = " or ip.Id == " + id;
        this.filter = this.filter.replace(this.#ipIdTemplate, ipId);
        this.passiveFilter = this.passiveFilter.replace(this.#ipIdTemplate, ipId);
    }
    #addMaxPayloadSizeStr(maxPayload) {
        const maxPayloadSizeStr = `and (tcp.PayloadLength ? tcp.PayloadLength < ${maxPayload} or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 or (tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 && tcp.Payload[2] <= 0x03): true)`;

        this.filter = filterString.replace(this.#maxPayloadSizeTemplate, maxPayloadSizeStr);
    }
    #finalizeFilterStrings() {
        this.filter = this.filter.replace(this.#ipIdTemplate, "");
        this.filter = this.filter.replace(this.#maxPayloadSizeTemplate, "");

        this.passiveFilter = this.passiveFilter.replace(this.#ipIdTemplate, "");
        this.passiveFilter = this.passiveFilter.replace(this.#maxPayloadSizeTemplate, "");
    }
}
/**
 * A class that handles packet manipulation and modification for DPI circumvention.
 * Provides functionality for packet fragmentation and window size modification.
 */
class Patcher {
    #patched;
    #headerReader;

    constructor() {
        this.#patched = false;
        this.#headerReader = new wd.HeaderReader();
        this.packetInfo = null;
        this.addrInfo = null;
    }

    /**
     * Sets and parses the packet buffer for processing
     * @param {Buffer} buffer - The packet buffer to process
     */
    setPacketBuffer(buffer) {
        this.#headerReader.setPacketBuffer(buffer);
        this.packetInfo = this.#headerReader.WinDivertHelperParsePacket();
        this.#patched = false;
    }

    /**
     * Sets and reads the address buffer
     * @param {Buffer} buffer - The address buffer to process
     */
    setAdressBuffer(buffer) {
        this.#headerReader.setAddressBuffer(buffer);
        this.addrInfo = this.#headerReader.readAddressData();
    }

    /**
     * Modifies the TCP window size of a packet
     * @param {Object} tcpHeader - The TCP header object
     * @param {number} windowSize - The new window size (1-65535)
     */
    changeWindowSize(tcpHeader, windowSize) {
        if (windowSize >= 1 && windowSize <= 65535) {
            tcpHeader.setWindow(windowSize);
            this.#patched = true;
        }
    }

    /**
     * Validates input parameters for packet fragmentation
     * @param {Object} winDivert - The WinDivert instance
     * @param {number} https_fragment_size - The size of the fragment
     * @throws {Error} If parameters are invalid or required data is missing
     */
    validateInputs(winDivert, https_fragment_size) {
        if (!winDivert) {
            throw new Error('winDivert parameter is required');
        }
        if (typeof https_fragment_size !== 'number' || https_fragment_size < 1) {
            throw new Error('https_fragment_size must be a valid positive number');
        }
        if (!this.#headerReader || !this.packetInfo) {
            throw new Error('HeaderReader or packetInfo is not initialized');
        }
    }

    /**
     * Calculates the appropriate fragment size based on packet type
     * @returns {number} The calculated fragment size
     */
    calculateFragmentSize() {
        if (this.packetInfo.isTLSHandshake && this.packetInfo.ServerNameOffset && this.packetInfo.ServerNameLength) {
            return this.packetInfo.ServerNameOffset - this.packetInfo.PayloadOffset;
        }
        return this.https_fragment_size;
    }

    /**
     * Creates two packet buffers for fragmentation
     * @param {number} https_fragment_size - The size to use for fragmentation
     * @returns {Object} An object containing firstBuffer and secondBuffer
     */
    createPacketBuffers(https_fragment_size) {
        const packetLength = this.#headerReader.packetLength;
        const sequenceNumber = this.packetInfo.ProtocolHeader.getSeqNum();
        
        // Create first buffer
        const firstSegmentSize = packetLength - this.packetInfo.PayloadLength + https_fragment_size;
        this.packetInfo.IpHeader.setLength(firstSegmentSize);
        const firstBuffer = new Uint8Array(firstSegmentSize);
        firstBuffer.set(this.#headerReader.packetBuffer.slice(0, firstSegmentSize));

        // Create second buffer
        const secondSegmentSize = packetLength - https_fragment_size;
        this.packetInfo.IpHeader.setLength(secondSegmentSize);
        this.packetInfo.ProtocolHeader.setSeqNum(sequenceNumber + https_fragment_size);
        const secondBuffer = new Uint8Array(secondSegmentSize);
        secondBuffer.set(this.#headerReader.packetBuffer.slice(0, firstSegmentSize - https_fragment_size), 0);
        secondBuffer.set(this.#headerReader.packetBuffer.slice(firstSegmentSize, packetLength), firstSegmentSize - https_fragment_size);

        // Reset original values
        this.packetInfo.ProtocolHeader.setSeqNum(sequenceNumber);
        this.packetInfo.IpHeader.setLength(packetLength);

        return { firstBuffer, secondBuffer };
    }

    /**
     * Sends a packet with recalculated checksums
     * @param {Object} winDivert - The WinDivert instance
     * @param {Buffer} buffer - The packet buffer to send
     * @returns {boolean} Success status of the operation
     */
    sendPacketWithChecksum(winDivert, buffer) {
        this.addrInfo.setIPChecksum(0);
        this.addrInfo.setTCPChecksum(0);
        
        const helper = winDivert.HelperCalcChecksums({ packet: buffer }, 0);
        if (helper.IPChecksum === 0 || helper.TCPChecksum === 0) {
            console.log("checksum error");
            return false;
        }

        this.addrInfo.setIPChecksum(helper.IPChecksum);
        this.addrInfo.setTCPChecksum(helper.TCPChecksum);
        winDivert.send({ packet: buffer, addr: this.#headerReader.addressBuffer });
        return true;
    }

    /**
     * Creates and sends fragmented packets
     * @param {Object} winDivert - The WinDivert instance
     * @param {number} https_fragment_size - The size to use for fragmentation
     * @returns {boolean} Success status of the operation
     * @throws {Error} If packet creation or sending fails
     */
    createFragmentPacket(winDivert, https_fragment_size = 2) {
        try {
            this.validateInputs(winDivert, https_fragment_size);
            
            if (!this.#headerReader.packetLength || !this.packetInfo.PayloadLength) {
                throw new Error('Packet length information is missing');
            }

            const { firstBuffer, secondBuffer } = this.createPacketBuffers(https_fragment_size);

            // Send packets with checksums
            if (!this.sendPacketWithChecksum(winDivert, secondBuffer)) return false;
            if (!this.sendPacketWithChecksum(winDivert, firstBuffer)) return false;

            return false;
        } catch (error) {
            console.error('createFragmentPacket error:', error.message);
            throw error;
        }
    }

}
/**
 * Main class for DPI circumvention implementation
 * Manages WinDivert instances and packet processing
 */
class GoodbyeDPI {
    #filter;
    #passiveWindivert;
    #quicWindivert;
    #activeWindivert;
    #patcher;
    #timeout;

    /**
     * Creates a new GoodbyeDPI instance
     * @param {number} timeout - Timeout in milliseconds before cleanup (default: 600000)
     */
    constructor(timeout = 600000) {
        this.#filter = Filter.getInstance();
        this.#patcher = new Patcher();
        this.#timeout = timeout;
    }

    /**
     * Initializes the DPI circumvention system
     * Sets up filters and WinDivert instances
     * @throws {Error} If initialization fails
     */
    async initialize() {
        try {
            this.#filter.generateFilters(null, null);
            await this.#initializeWindivert();
            this.#setupPacketListener();
            this.#setupCleanupTimeout();
        } catch (error) {
            console.error("Initialization error:", error);
            this.cleanup();
            throw error;
        }
    }

    /**
     * Initializes WinDivert instances for different packet handling scenarios
     * @private
     */
    async #initializeWindivert() {
        // Initialize passive windivert
        this.#passiveWindivert = await wd.createWindivert(
            this.#filter.passiveFilter,
            wd.LAYERS.NETWORK,
            wd.FLAGS.DROP
        );
        this.#passiveWindivert.open();

        // Initialize QUIC windivert
        this.#quicWindivert = await wd.createWindivert(
            this.#filter.quicBlockPassiveFilter,
            wd.LAYERS.NETWORK,
            wd.FLAGS.DROP
        );
        this.#quicWindivert.open();

        // Initialize active windivert
        this.#activeWindivert = await wd.createWindivert(
            this.#filter.filter,
            wd.LAYERS.NETWORK,
            wd.FLAGS.DEFAULT
        );
        this.#activeWindivert.open();
    }

    /**
     * Sets up the packet listener for processing network traffic
     * @private
     */
    #setupPacketListener() {
        wd.addReceiveListener(this.#activeWindivert, (packet, addr) => {
            this.#handlePacket(packet, addr);
        });
    }

    /**
     * Handles incoming packets and determines if they need fragmentation
     * @param {Buffer} packet - The packet buffer
     * @param {Buffer} addr - The address buffer
     * @private
     */
    #handlePacket(packet, addr) {
        this.#patcher.setAdressBuffer(addr);
        this.#patcher.setPacketBuffer(packet);

        if (this.#shouldFragmentPacket()) {
            return this.#patcher.createFragmentPacket(this.#activeWindivert, 2);
        }
    }

    /**
     * Determines if a packet should be fragmented based on its properties
     * @returns {boolean} True if the packet should be fragmented
     * @private
     */
    #shouldFragmentPacket() {
        const packetInfo = this.#patcher.packetInfo;
        const addrInfo = this.#patcher.addrInfo;

        return (
            packetInfo.Protocol === wd.PROTOCOLS.TCP &&
            packetInfo.FragOff === 0 &&
            addrInfo.getOutbound() &&
            (packetInfo.PayloadLength === 2 || packetInfo.PayloadLength > 16) &&
            packetInfo.ProtocolHeader.getDstPort() !== 80 &&
            packetInfo.isTLSHandshake
        );
    }

    /**
     * Sets up the cleanup timeout
     * @private
     */
    #setupCleanupTimeout() {
        setTimeout(() => {
            this.cleanup();
        }, this.#timeout);
    }

    /**
     * Cleans up resources and closes WinDivert instances
     */
    cleanup() {
        try {
            this.#activeWindivert?.close();
            this.#quicWindivert?.close();
            this.#passiveWindivert?.close();
        } catch (error) {
            console.error("Cleanup error:", error);
        }
    }
}

// Initialize and start
(async () => {
    const goodbyeDPI = new GoodbyeDPI();
    await goodbyeDPI.initialize();
})();