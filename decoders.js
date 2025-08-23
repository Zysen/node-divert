/**
 * @fileoverview This module provides packet header decoding functionality for network packets.
 * It includes utilities for parsing IP, TCP, UDP, and ICMP headers as well as TLS handshake detection.
 * 
 * @module decoders
 */

const UINT32_SIZE_BYTES = 4;

/**
 * Performs a 16-bit byte swap operation
 * @param {number} value - The value to byte swap
 * @returns {number} The byte swapped value
 */
function BYTESWAP16(value) {
  return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF);
}

/**
 * Class for reading and parsing network packet headers
 * Supports IPv4, IPv6, TCP, UDP, ICMP headers and TLS handshake detection
 */
class HeaderReader {
  /**
   * Creates a new HeaderReader instance
   */
  constructor() {
  }

  /**
   * Sets the packet buffer to read headers from
   * @param {Buffer|Uint8Array} packetBuffer - The buffer containing packet data
   * @throws {TypeError} If packetBuffer is not a Buffer or Uint8Array
   */
  setPacketBuffer(packetBuffer) {
    if ((Buffer && !Buffer.isBuffer(packetBuffer)) && !(packetBuffer instanceof Uint8Array)) {
      throw new TypeError('packetBuffer must be a Buffer or Uint8Array');
    }
    this.packetBuffer = packetBuffer;
    this.packetDataView = new DataView(packetBuffer.buffer);
    this.packetLength = packetBuffer.buffer.byteLength||packetBuffer.length;
  }

  /**
   * Sets the address buffer containing network address information
   * @param {Buffer|Uint8Array} addressBuffer - The buffer containing address data
   * @throws {TypeError} If addressBuffer is not a Buffer or Uint8Array
   */
  setAddressBuffer(addressBuffer) {
    if (!Buffer.isBuffer(addressBuffer) && !(addressBuffer instanceof Uint8Array)) {
      throw new TypeError('packetBuffer must be a Buffer or Uint8Array');
    }
    this.addressBuffer = addressBuffer;
    this.addressDataView = new DataView(addressBuffer.buffer);
  }

  /**
   * Reads an IPv4 header from the packet buffer
   * @param {number} offset - Offset into the packet buffer
   * @returns {Object} Object containing IPv4 header field getters and setters
   */
  #readIPHdr(offset) {
    const IP_HEADER_MIN_SIZE = 20;

    if (this.packetLength < IP_HEADER_MIN_SIZE) {
      console.warn(`Insufficient buffer size. Must be at least ${IP_HEADER_MIN_SIZE} bytes.`);
      return false;
    }

    const getHdrLength = () => this.packetDataView.getUint8(offset + 0) & 0b00001111; 
    const getVersion = () => (this.packetDataView.getUint8(offset + 0) & 0b11110000) >>> 4; 
    
    const setHdrLength = (value) => {
      const hdrLengthVersion = (this.packetDataView.getUint8(offset + 0) & 0b00001111) | (value << 4);
      this.packetDataView.setUint8(offset + 0, hdrLengthVersion);
    };

    const setVersion = (value) => {
      const hdrLengthVersion = (this.packetDataView.getUint8(offset + 0) & 0b11110000) | value;
      this.packetDataView.setUint8(offset + 0, hdrLengthVersion);
    };

    const getTos = () => this.packetDataView.getUint8(offset + 1);
    const setTos = (value) => this.packetDataView.setUint8(offset + 1, value);

    const getLength = () => this.packetDataView.getUint16(offset + 2);
    const setLength = (value) => this.packetDataView.setUint16(offset + 2, value);

    const getId = () => this.packetDataView.getUint16(offset + 4);
    const setId = (value) => this.packetDataView.setUint16(offset + 4, value);

    const getFragOff0 = () => this.packetDataView.getUint16(offset + 6);
    const setFragOff0 = (value) => this.packetDataView.setUint16(offset + 6, value);

    const getTtl = () => this.packetDataView.getUint8(offset + 8);
    const setTtl = (value) => this.packetDataView.setUint8(offset + 8, value);

    const getProtocol = () => this.packetDataView.getUint8(offset + 9);
    const setProtocol = (value) => this.packetDataView.setUint8(offset + 9, value);

    const getChecksum = () => this.packetDataView.getUint16(offset + 10);
    const setChecksum = (value) => this.packetDataView.setUint16(offset + 10, value);

    const getSrcAddr = () => {
      const address = this.packetDataView.getUint32(offset + 12);
      return {
        valueOf: () => address,
        toString: () => (((address >> 24) & 0xFF) + "." + 
        ((address >> 16) & 0xFF) + "." + 
        ((address >> 8) & 0xFF) + "." +  
        (address & 0xFF)),
        [Symbol.toPrimitive](hint) {
          return hint === 'number' ? this.valueOf() : this.toString();
        }
      };
    };
    const setSrcAddr = (value) => this.packetDataView.setUint32(offset + 12, +value);

    const getDstAddr = () => {
      const address = this.packetDataView.getUint32(offset + 16);
      return {
        valueOf: () => address,
        toString: () => (((address >> 24) & 0xFF) + "." + 
        ((address >> 16) & 0xFF) + "." + 
        ((address >> 8) & 0xFF) + "." +  
        (address & 0xFF)),
        [Symbol.toPrimitive](hint) {
          return hint === 'number' ? this.valueOf() : this.toString();
        }
      };  
    };
    const setDstAddr = (value) => this.packetDataView.setUint32(offset + 16, +value);

    const getFragOff = () => getFragOff0() & 0x1FFF;
    const getMoreFragment = () => (getFragOff0() & 0x2000) !== 0;
    const getDontFragment = () => (getFragOff0() & 0x4000) !== 0;
    const getReserved = () => (getFragOff0() & 0x8000) !== 0;

    const setFragOff = (value) => {
      const fragOff0 = (getFragOff0() & 0xE000) | (value & 0x1FFF);
      setFragOff0(fragOff0);
    };

    const setMoreFragment = (value) => {
      const fragOff0 = (getFragOff0() & 0xDFFF) | ((value & 0x0001) << 13);
      setFragOff0(fragOff0);
    };

    const setDontFragment = (value) => {
      const fragOff0 = (getFragOff0() & 0xBFFF) | ((value & 0x0001) << 14);
      setFragOff0(fragOff0);
    };

    const setReserved = (value) => {
      const fragOff0 = (getFragOff0() & 0x7FFF) | ((value & 0x0001) << 15);
      setFragOff0(fragOff0);
    };

    return {
      getHdrLength, setHdrLength,
      getVersion, setVersion,
      getTos, setTos,
      getLength, setLength,
      getId, setId,
      getFragOff0, setFragOff0,
      getTtl, setTtl,
      getProtocol, setProtocol,
      getChecksum, setChecksum,
      getSrcAddr, setSrcAddr,
      getDstAddr, setDstAddr,
      getFragOff, setFragOff,
      getMF: getMoreFragment, setMF: setMoreFragment,
      getDF: getDontFragment, setDF: setDontFragment,
      getReserved, setReserved
    };
  }

  /**
   * Reads an IPv6 header from the packet buffer
   * @param {number} offset - Offset into the packet buffer
   * @returns {Object} Object containing IPv6 header field getters and setters
   */
  #readIPv6Hdr(offset) {
    const getVersion = () => (this.packetDataView.getUint8(offset + 0) & 0xF0) >> 4;
    const getTrafficClass0 = () => (this.packetDataView.getUint8(offset + 0) & 0x0F);
    const getTrafficClass1 = () => (this.packetDataView.getUint8(offset + 1) & 0xF0) >> 4;
    const getTrafficClass = () => (getTrafficClass0() << 4) | getTrafficClass1();
    const getFlowLabel0 = () => (this.packetDataView.getUint8(offset + 1) & 0x0F);
    const getFlowLabel1 = () => this.packetDataView.getUint16(offset + 2);
    const getFlowLabel = () => (getFlowLabel0() << 16) | getFlowLabel1();
    const getLength = () => this.packetDataView.getUint16(offset + 4);
    const getNextHdr = () => this.packetDataView.getUint8(offset + 6);
    const getHopLimit = () => this.packetDataView.getUint8(offset + 7);
    const getSrcAddr = () => [
      this.packetDataView.getUint32(offset + 8),
      this.packetDataView.getUint32(offset + 12),
      this.packetDataView.getUint32(offset + 16),
      this.packetDataView.getUint32(offset + 20)
    ];
    const getDstAddr = () => [
      this.packetDataView.getUint32(offset + 24),
      this.packetDataView.getUint32(offset + 28),
      this.packetDataView.getUint32(offset + 32),
      this.packetDataView.getUint32(offset + 36)
    ];

    const setVersion = (value) => {
      const current = this.packetDataView.getUint8(offset + 0);
      this.packetDataView.setUint8(offset + 0, (current & 0x0F) | ((value & 0x0F) << 4));
    };
    const setTrafficClass0 = (value) => {
      const current = this.packetDataView.getUint8(offset + 0);
      this.packetDataView.setUint8(offset + 0, (current & 0xF0) | (value & 0x0F));
    };
    const setTrafficClass1 = (value) => {
      const current = this.packetDataView.getUint8(offset + 1);
      this.packetDataView.setUint8(offset + 1, (current & 0x0F) | ((value & 0x0F) << 4));
    };
    const setTrafficClass = (value) => {
      setTrafficClass0((value & 0xF0) >> 4);
      setTrafficClass1(value & 0x0F);
    };
    const setFlowLabel0 = (value) => {
      const current = this.packetDataView.getUint8(offset + 1);
      this.packetDataView.setUint8(offset + 1, (current & 0xF0) | (value & 0x0F));
    };
    const setFlowLabel1 = (value) => {
      this.packetDataView.setUint16(offset + 2, value);
    };
    const setFlowLabel = (value) => {
      setFlowLabel0((value & 0xF0000) >> 16);
      setFlowLabel1(value & 0xFFFF);
    };
    const setLength = (value) => this.packetDataView.setUint16(offset + 4, value);
    const setNextHdr = (value) => this.packetDataView.setUint8(offset + 6, value);
    const setHopLimit = (value) => this.packetDataView.setUint8(offset + 7, value);
    const setSrcAddr = (value) => {
      this.packetDataView.setUint32(offset + 8, value[0]);
      this.packetDataView.setUint32(offset + 12, value[1]);
      this.packetDataView.setUint32(offset + 16, value[2]);
      this.packetDataView.setUint32(offset + 20, value[3]);
    };
    const setDstAddr = (value) => {
      this.packetDataView.setUint32(offset + 24, value[0]);
      this.packetDataView.setUint32(offset + 28, value[1]);
      this.packetDataView.setUint32(offset + 32, value[2]);
      this.packetDataView.setUint32(offset + 36, value[3]);
    };

    return {
      getVersion, setVersion,
      getTrafficClass0, setTrafficClass0,
      getTrafficClass1, setTrafficClass1,
      getTrafficClass, setTrafficClass,
      getFlowLabel0, setFlowLabel0,
      getFlowLabel1, setFlowLabel1,
      getFlowLabel, setFlowLabel,
      getLength, setLength,
      getNextHdr, setNextHdr,
      getHopLimit, setHopLimit,
      getSrcAddr, setSrcAddr,
      getDstAddr, setDstAddr
    };
  }

  /**
   * Reads ICMP header from the packet buffer
   * @private
   * @param {number} offset - Offset into the packet buffer
   * @returns {Object} Object containing ICMP header field getters and setters
   */
  #readIcmpHdr(offset) {
    const getType = () => this.packetDataView.getUint8(offset + 0);
    const setType = (value) => this.packetDataView.setUint8(offset + 0, value);

    const getCode = () => this.packetDataView.getUint8(offset + 1);
    const setCode = (value) => this.packetDataView.setUint8(offset + 1, value);

    const getChecksum = () => this.packetDataView.getUint16(offset + 2);
    const setChecksum = (value) => this.packetDataView.setUint16(offset + 2, value); 

    const getBody = () => this.packetDataView.getUint32(offset + 4);
    const setBody = (value) => this.packetDataView.setUint32(offset + 4, value);

    return {
      getType, setType,
      getCode, setCode,
      getChecksum, setChecksum,
      getBody, setBody
    };
  }

  /**
   * Reads TCP header from the packet buffer
   * @private
   * @param {number} offset - Offset into the packet buffer
   * @returns {Object} Object containing TCP header field getters and setters
   */
  #readTcpHdr(offset) {
    const getSrcPort = () => this.packetDataView.getUint16(offset + 0);
    const setSrcPort = (value) => this.packetDataView.setUint16(offset + 0, value);

    const getDstPort = () => this.packetDataView.getUint16(offset + 2); 
    const setDstPort = (value) => this.packetDataView.setUint16(offset + 2, value);

    const getSeqNum = () => this.packetDataView.getUint32(offset + 4); 
    const setSeqNum = (value) => this.packetDataView.setUint32(offset + 4, value);

    const getAckNum = () => this.packetDataView.getUint32(offset + 8); 
    const setAckNum = (value) => this.packetDataView.setUint32(offset + 8, value);
    
    const getFlags = () => this.packetDataView.getUint16(offset + 12); 
    const setFlags = (value) => this.packetDataView.setUint16(offset + 12, value);
    
    const getReserved1 = () => (getFlags() & 0xF000) >>> 12; 
    const setReserved1 = (value) => {
      const flags = getFlags();
      setFlags((flags & 0x0FFF) | ((value & 0xF) << 12));
    };

    const getHdrLength = () => (getFlags() >> 12) & 0x0F; 
    const setHdrLength = (value) => {
      const flags = getFlags();
      setFlags((flags & 0xF0FF) | ((value & 0xF) << 8));
    };

    const getFin = () => (getFlags() & 0x01) !== 0; 
    const setFin = (value) => {
      const flags = getFlags();
      setFlags(value ? (flags | 0x01) : (flags & ~0x01));
    };

    const getSyn = () => (getFlags() & 0x02) !== 0;
    const setSyn = (value) => {
      const flags = getFlags();
      setFlags(value ? (flags | 0x02) : (flags & ~0x02));
    };

    const getRst = () => (getFlags() & 0x04) !== 0; 
    const setRst = (value) => {
      const flags = getFlags();
      setFlags(value ? (flags | 0x04) : (flags & ~0x04));
    };

    const getPush = () => (getFlags() & 0x08) !== 0; 
    const setPush = (value) => {
      const flags = getFlags();
      setFlags(value ? (flags | 0x08) : (flags & ~0x08));
    };

    const getAck = () => (getFlags() & 0x10) !== 0; 
    const setAck = (value) => {
      const flags = getFlags();
      setFlags(value ? (flags | 0x10) : (flags & ~0x10));
    };

    const getUrgent = () => (getFlags() & 0x20) !== 0;
    const setUrgent = (value) => {
      const flags = getFlags();
      setFlags(value ? (flags | 0x20) : (flags & ~0x20));
    };

    const getReserved2 = () => (getFlags() & 0xC0) >>> 6;
    const setReserved2 = (value) => {
      const flags = getFlags();
      setFlags((flags & 0x3F) | ((value & 0x3) << 6));
    };

    const getWindow = () => this.packetDataView.getUint16(offset + 14); 
    const setWindow = (value) => this.packetDataView.setUint16(offset + 14, value);

    const getChecksum = () => this.packetDataView.getUint16(offset + 16); 
    const setChecksum = (value) => this.packetDataView.setUint16(offset + 16, value);

    const getUrgPtr = () => this.packetDataView.getUint16(offset + 18); 
    const setUrgPtr = (value) => this.packetDataView.setUint16(offset + 18, value);

    return {
      getSrcPort, setSrcPort,
      getDstPort, setDstPort,
      getSeqNum, setSeqNum,
      getAckNum, setAckNum,
      getReserved1, setReserved1,
      getHdrLength, setHdrLength,
      getFin, setFin,
      getSyn, setSyn,
      getRst, setRst,
      getPsh: getPush, setPsh: setPush,
      getAck, setAck,
      getUrg: getUrgent, setUrg: setUrgent,
      getReserved2, setReserved2,
      getWindow, setWindow,
      getChecksum, setChecksum,
      getUrgPtr, setUrgPtr
    };
  }

  /**
   * Reads UDP header from the packet buffer
   * @private
   * @param {number} offset - Offset into the packet buffer
   * @returns {Object} Object containing UDP header field getters and setters
   */
  #readUdpHdr(offset) {
    const getSrcPort = () => this.packetDataView.getUint16(offset + 0); 
    const setSrcPort = (value) => this.packetDataView.setUint16(offset + 0, value);

    const getDstPort = () => this.packetDataView.getUint16(offset + 2); 
    const setDstPort = (value) => this.packetDataView.setUint16(offset + 2, value);

    const getLength = () => this.packetDataView.getUint16(offset + 4); 
    const setLength = (value) => this.packetDataView.setUint16(offset + 4, value);

    const getChecksum = () => this.packetDataView.getUint16(offset + 6); 
    const setChecksum = (value) => this.packetDataView.setUint16(offset + 6, value);

    return {
      getSrcPort, setSrcPort,
      getDstPort, setDstPort,
      getLength, setLength,
      getChecksum, setChecksum
    };
  }

  /**
   * Reads network interface data from the address buffer
   * @private
   * @param {number} offset - Offset into the address buffer
   * @returns {Object} Object containing network interface data getters and setters
   */
  #readNetworkData(offset) {
    const getIfIdx = () => this.addressDataView.getUint32(offset + 0); 
    const setIfIdx = (value) => this.addressDataView.setUint32(offset + 0, value);

    const getSubIfIdx = () => this.addressDataView.getUint32(offset + 4); 
    const setSubIfIdx = (value) => this.addressDataView.setUint32(offset + 4, value);

    return {
      getIfIdx, setIfIdx,
      getSubIfIdx, setSubIfIdx
    };
  }

  /**
   * Reads flow/socket data from the address buffer
   * @private
   * @param {number} offset - Offset into the address buffer
   * @returns {Object} Object containing flow/socket data getters and setters
   */
  #readFlowOrSocketData(offset) {
    const getEndpointId = () => this.addressDataView.getBigUint64(offset + 0);
    const setEndpointId = (value) => this.addressDataView.setBigUint64(offset + 0, value);

    const getParentEndpointId = () => this.addressDataView.getBigUint64(offset + 8); 
    const setParentEndpointId = (value) => this.addressDataView.setBigUint64(offset + 8, value);

    const getProcessId = () => this.addressDataView.getUint32(offset + 16); 
    const setProcessId = (value) => this.addressDataView.setUint32(offset + 16, value);

    const getLocalAddr = () => [
      this.addressDataView.getUint32(offset + 20, true),
      this.addressDataView.getUint32(offset + 24, true),
      this.addressDataView.getUint32(offset + 28, true),
      this.addressDataView.getUint32(offset + 32, true)
    ];
    const setLocalAddr = (value) => {
      this.addressDataView.setUint32(offset + 20, value[0]);
      this.addressDataView.setUint32(offset + 24, value[1]);
      this.addressDataView.setUint32(offset + 28, value[2]);
      this.addressDataView.setUint32(offset + 32, value[3]);
    };

    const getRemoteAddr = () => [
      this.addressDataView.getUint32(offset + 36, true),
      this.addressDataView.getUint32(offset + 40, true),
      this.addressDataView.getUint32(offset + 44, true),
      this.addressDataView.getUint32(offset + 48, true)
    ];
    const setRemoteAddr = (value) => {
      this.addressDataView.setUint32(offset + 36, value[0]);
      this.addressDataView.setUint32(offset + 40, value[1]);
      this.addressDataView.setUint32(offset + 44, value[2]);
      this.addressDataView.setUint32(offset + 48, value[3]);
    };

    const getLocalPort = () => this.addressDataView.getUint16(offset + 52);
    const setLocalPort = (value) => this.addressDataView.setUint16(offset + 52, value);

    const getRemotePort = () => this.addressDataView.getUint16(offset + 54);
    const setRemotePort = (value) => this.addressDataView.setUint16(offset + 54, value);

    const getProtocol = () => this.addressDataView.getUint8(offset + 56); 
    const setProtocol = (value) => this.addressDataView.setUint8(offset + 56, value);

    return {
      getEndpointId, setEndpointId,
      getParentEndpointId, setParentEndpointId,
      getProcessId, setProcessId,
      getLocalAddr, setLocalAddr,
      getRemoteAddr, setRemoteAddr,
      getLocalPort, setLocalPort,
      getRemotePort, setRemotePort,
      getProtocol, setProtocol
    };
  }

  /**
   * Reads reflection data from the address buffer
   * @private
   * @param {number} offset - Offset into the address buffer
   * @returns {Object} Object containing reflection data getters and setters
   */
  #readReflectData(offset) {
    const getTimestamp = () => this.addressDataView.getBigUint64(offset + 0);
    const setTimestamp = (value) => this.addressDataView.setBigUint64(offset + 0, value);

    const getProcessId = () => this.addressDataView.getUint32(offset + 8);
    const setProcessId = (value) => this.addressDataView.setUint32(offset + 8, value);

    const getLayer = () => this.addressDataView.getUint8(offset + 12);
    const setLayer = (value) => this.addressDataView.setUint8(offset + 12, value);

    const getFlags = () => this.addressDataView.getBigUint64(offset + 16); 
    const setFlags = (value) => this.addressDataView.setBigUint64(offset + 16, value);

    const getPriority = () => this.addressDataView.getInt16(offset + 24);
    const setPriority = (value) => this.addressDataView.setInt16(offset + 24, value);

    return {
      getTimestamp, setTimestamp,
      getProcessId, setProcessId,
      getLayer, setLayer,
      getFlags, setFlags,
      getPriority, setPriority
    };
  }

  /**
   * Reads address data from the address buffer
   * @param {number} offset - Offset into the address buffer
   * @returns {Object} Object containing address data getters and setters
   */
  readAddressData(offset) {
    const getTimestamp = () => this.addressDataView.getBigUint64(offset + 0); 
    const setTimestamp = (value) => this.addressDataView.setBigUint64(offset + 0, value);

    const getLayer = () => this.addressDataView.getUint8(offset + 8) & 0xFF;
    const setLayer = (value) => this.addressDataView.setUint8(offset + 8, value & 0xFF);

    const getEvent = () => (this.addressDataView.getUint8(offset + 9) & 0xFF);
    const setEvent = (value) => this.addressDataView.setUint8(offset + 9, value & 0xFF);

    const getSniffed = () => (this.addressDataView.getUint8(offset + 10) & 0x01) !== 0; 
    const setSniffed = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x01) : (current & ~0x01));
    };

    const getOutbound = () => (this.addressDataView.getUint8(offset + 10) & 0x02) !== 0; 
    const setOutbound = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x02) : (current & ~0x02));
    };

    const getLoopback = () => (this.addressDataView.getUint8(offset + 10) & 0x04) !== 0; 
    const setLoopback = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x04) : (current & ~0x04));
    };

    const getImpostor = () => (this.addressDataView.getUint8(offset + 10) & 0x08) !== 0;
    const setImpostor = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x08) : (current & ~0x08));
    };

    const getIPv6 = () => (this.addressDataView.getUint8(offset + 10) & 0x10) !== 0; 
    const setIPv6 = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x10) : (current & ~0x10));
    };

    const getIPChecksum = () => (this.addressDataView.getUint8(offset + 10) & 0x20) !== 0;
    const setIPChecksum = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x20) : (current & ~0x20));
    };

    const getTCPChecksum = () => (this.addressDataView.getUint8(offset + 10) & 0x40) !== 0; 
    const setTCPChecksum = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x40) : (current & ~0x40));
    };

    const getUDPChecksum = () => (this.addressDataView.getUint8(offset + 10) & 0x80) !== 0; 
    const setUDPChecksum = (value) => {
      const current = this.addressDataView.getUint8(offset + 10);
      this.addressDataView.setUint8(offset + 10, value ? (current | 0x80) : (current & ~0x80));
    };

    const getReserved1 = () => this.addressDataView.getUint8(offset + 11) & 0xFF; 
    const setReserved1 = (value) => this.addressDataView.setUint8(offset + 11, value & 0xFF);

    const getReserved2 = () => this.addressDataView.getUint32(offset + 12); 
    const setReserved2 = (value) => this.addressDataView.setUint32(offset + 12, value);

    // Union
    const layer = getLayer();

    let readLayerHdr;
    switch (layer) {
      case 0:
        readLayerHdr = this.#readNetworkData(offset + 16);
        break;
      case 1:
      case 2:
        readLayerHdr = this.#readFlowOrSocketData(offset + 16);
        break;
      case 3:
        readLayerHdr = this.#readReflectData(offset + 16);
        break;
      default:
        readLayerHdr=null;
       // console.warn("Unknown layer type:"+layer);
    }

    return {
      getTimestamp, setTimestamp,
      getLayer, setLayer,
      getEvent, setEvent,
      getSniffed, setSniffed,
      getOutbound, setOutbound,
      getLoopback, setLoopback,
      getImpostor, setImpostor,
      getIPv6, setIPv6,
      getIPChecksum, setIPChecksum,
      getTCPChecksum, setTCPChecksum,
      getUDPChecksum, setUDPChecksum,
      getReserved1, setReserved1,
      getReserved2, setReserved2,
      readLayerHdr
    };
  }

  /**
   * Reads IPv6 fragmentation header
   * @param {number} [offset=0] - Offset into the packet buffer
   * @returns {Object} Object containing IPv6 fragmentation header getters and setters
   */
  #readIpv6FragHdr(offset = 0) {
    
    const getNextHdr = () => this.dataView.getUint8(offset);
    const setNextHdr = (value) => this.dataView.setUint8(offset, value);
    
    const getReserved = () => this.dataView.getUint8(offset + 1);
    const setReserved = (value) => this.dataView.setUint8(offset + 1, value);
    
    const getFragOff0 = () => this.dataView.getUint16(offset + 2); 
    const setFragOff0 = (value) => this.dataView.setUint16(offset + 2, value);
   
    const getFragOff = () => getFragOff0() & 0xF8FF; 
    
    const getMF = () => (getFragOff0() & 0x0100) !== 0; 
   
    const getId = () => this.dataView.getUint32(offset + 4); 
    const setId = (value) => this.dataView.setUint32(offset + 4, value);

    
    return {
      getNextHdr, setNextHdr,
      getReserved, setReserved,
      getFragOff0, setFragOff0,
      getId, setId,
      getFragOff,
      getMF
    };
  }

  /**
   * Checks if the packet contains a TLS handshake
   * @private
   * @param {Object} info - Packet information object
   * @returns {boolean} True if packet contains TLS handshake, false otherwise
   */
  #isTLSHandshake(info) {
    if (!info || !info.dataLength || info.dataOffset===-1) return false;    
    
    info.isTLSHandshake = (
      (info.dataLength === 2 && 
       this.packetBuffer[info.dataOffset] === 0x16 && 
       this.packetBuffer[info.dataOffset + 1] === 0x03) ||
      (info.dataLength >= 3 && 
       this.packetBuffer[info.dataOffset] === 0x16 && 
       this.packetBuffer[info.dataOffset + 1] === 0x03 && 
       (this.packetBuffer[info.dataOffset + 2] === 0x01 || 
        this.packetBuffer[info.dataOffset + 2] === 0x03))
    );
    return info.isTLSHandshake;
  }


  /**
   * Extracts Server Name Indication (SNI) from TLS handshake
   * @private
   * @param {Object} info - Packet information object
   */
  #extractSni(info) {
    if (!info || !info.dataLength || info.dataOffset===-1) return;
    const HOST_MAXLEN = 253; 
    let ptr = info.dataOffset;
    const pktlen = this.packetBuffer.length;

    while (ptr + 8 < pktlen) {
        
        if (
            this.packetBuffer[ptr] === 0 &&
            this.packetBuffer[ptr + 1] === 0 &&
            this.packetBuffer[ptr + 2] === 0 &&
            this.packetBuffer[ptr + 4] === 0 &&
            this.packetBuffer[ptr + 6] === 0 &&
            this.packetBuffer[ptr + 7] === 0 &&
            
            this.packetBuffer[ptr + 3] - this.packetBuffer[ptr + 5] === 2 &&
            this.packetBuffer[ptr + 5] - this.packetBuffer[ptr + 8] === 3
        ) {
            
            const hnlen = this.packetBuffer[ptr + 8];
            if (ptr + 8 + hnlen > pktlen) {
                return;
            }
           
            if (hnlen < 3 || hnlen > HOST_MAXLEN) {
                return; 
            }
            
            for (let i = 0; i < hnlen; i++) {
                const char = this.packetBuffer[ptr + 9 + i];
                if (
                    !(
                        (char >= 48 && char <= 57) || // 0-9
                        (char >= 97 && char <= 122) || // a-z
                        char === 46 || // .
                        char === 45 // -
                    )
                ) {
                    return; 
                }
            }
           
            info.sniOffset=ptr+9;
            info.sniLength=hnlen;
            return;
        }
        ptr++;
    }

    return;
  }

  /**
   * Helper function to parse a complete network packet
   * Detects packet type and parses appropriate headers
   * @returns {Object|null} Parsed packet information or null if invalid
   */
  WinDivertHelperParsePacket() {
    const version = (this.packetDataView.getUint8(0) & 0b11110000) >>> 4;
    const packetInfo = {
      dataOffset: -1,
      protocol: null,
      protocolHeader: null,
      fragHeader: null,
      ipHeader: null,
      packetLength: null,
      totalLength: null,
      headerLength: null,
      fragOff: 0,
      MF: false,
      fragment: false,
      dataLength: 0,
      isTLSHandshake: false,
      sniOffset: -1,
      sniLength: 0,
    };
    
    if (!this.#parseIPPacket(version, packetInfo)) {
      return null;
    }   
    
    if (packetInfo.fragOff === 0) {
      this.#parseProtocolHeader(packetInfo);
    }

    if (packetInfo.totalLength > this.packetLength) {
      return null;
    }
    if (this.#isTLSHandshake(packetInfo)) {     
      this.#extractSni(packetInfo); 
    }

    return {
      Protocol: packetInfo.protocol,
      Fragment: packetInfo.fragment ? 1 : 0,
      MF: packetInfo.MF ? 1 : 0,
      FragOff: packetInfo.fragOff,
      Truncated: 0,
      Extended: (packetInfo.totalLength > this.packetLength ? 1 : 0),
      Reserved1: 0,
      IpHeader: packetInfo.ipHeader,
      ProtocolHeader: packetInfo.protocolHeader,
      PayloadOffset: packetInfo.dataLength === 0 ? null : packetInfo.dataOffset,
      HeaderLength: packetInfo.headerLength,
      PayloadLength: packetInfo.dataLength,
      isTLSHandshake:packetInfo.isTLSHandshake,
      ServerNameOffset:packetInfo.sniOffset===-1 ? null :packetInfo.sniOffset,
      ServerNameLength:packetInfo.sniLength,
      PacketNextOffset: packetInfo.totalLength > this.packetLength ? 
        (packetInfo.headerLength + packetInfo.headerLength) : null,
      PacketNextLength: this.packetLength - packetInfo.headerLength - packetInfo.dataLength
    };
  }

  /**
   * Parses IP packet based on version
   * @private
   * @param {number} version - IP version (4 or 6)
   * @param {Object} info - Packet information object
   * @returns {boolean} True if parsing successful, false otherwise
   */
  #parseIPPacket(version, info) {
    if (version === 4) {
      info.dataOffset=0;
      return this.#parseIPv4Packet(info);
    } else if (version === 6) {
      info.dataOffset=0;
      return this.#parseIPv6Packet(info);
    }
    return false;
  }

  /**
   * Parses IPv4 packet
   * @private
   * @param {Object} info - Packet information object
   * @returns {boolean} True if parsing successful, false otherwise
   */
  #parseIPv4Packet(info) {
    const hdrLength = this.packetDataView.getUint8(0) & 0b00001111;
    
    if (this.packetLength < 20 || hdrLength < 5) {
      console.warn("Invalid packet length");
      return false;
    }

    info.ipHeader = this.#readIPHdr(info.dataOffset);
    info.protocol = info.ipHeader.getProtocol();
    info.totalLength = info.ipHeader.getLength();
    info.headerLength = info.ipHeader.getHdrLength() * UINT32_SIZE_BYTES;

    if (info.totalLength < info.headerLength || this.packetLength < info.headerLength) {
      console.warn("Invalid header length");
      return false;
    }

    info.fragOff = info.ipHeader.getFragOff();
    info.MF = info.ipHeader.getMF();
    info.fragment = (info.MF || info.fragOff !== 0);    
    info.packetLength = Math.min(info.totalLength, this.packetLength);
    info.dataOffset += info.headerLength;
    info.dataLength = info.packetLength - info.headerLength;

    return true;
  }

  /**
   * Parses protocol-specific header (TCP, UDP, ICMP)
   * @private
   * @param {Object} info - Packet information object
   */
  #parseProtocolHeader(info) {
    const PROTOCOL_HANDLERS = {
      6: () => this.#parseTCPHeader(info),    // IPPROTO_TCP
      17: () => this.#parseUDPHeader(info),   // IPPROTO_UDP
      1: () => this.#parseICMPHeader(info),   // IPPROTO_ICMP
      58: () => this.#parseICMPHeader(info)   // IPPROTO_ICMPV6
    };

    const handler = PROTOCOL_HANDLERS[info.protocol];
    if (handler) {
      handler();
    } else {
      info.dataOffset -= info.headerLength;
      info.dataLength += info.headerLength;
    }
    
    
    
    info.dataOffset += info.headerLength;
    info.dataLength -= info.headerLength;
  }

  /**
   * Parses IPv6 packet
   * @private
   * @param {Object} info - Packet information object
   * @returns {boolean} True if parsing successful, false otherwise
   */
  #parseIPv6Packet(info) {
    if (this.packetLength < 40) {
      console.warn("Invalid packet length");
      return false;
    }

    info.ipHeader = this.#readIPv6Hdr(info.dataOffset);
    info.protocol = info.ipHeader.getNextHdr();
    info.totalLength = info.ipHeader.getLength() + 40;
    info.packetLength = Math.min(info.totalLength, this.packetLength);
    info.dataOffset = 40;
    info.dataLength = info.packetLength - 40;

    return this.#parseIPv6ExtHeaders(info);
  }

  /**
   * Parses IPv6 extension headers
   * @private
   * @param {Object} info - Packet information object
   * @returns {boolean} True if parsing successful, false otherwise
   */
  #parseIPv6ExtHeaders(info) {
    while (info.fragOff === 0 && info.dataLength >= 2) {
      const headerLength = this.packetDataView.getUint8(info.dataOffset + 1);
      let isExtHeader = true;

      switch (info.protocol) {
        case 44: // IPPROTO_FRAGMENT
          if (!this.#handleIPv6FragmentHeader(info, 8)) {
            isExtHeader = false;
          }
          break;
        case 51: // IPPROTO_AH
          info.headerLength = (headerLength + 2) * 4;
          break;
        case 0:  // IPPROTO_HOPOPTS
        case 60: // IPPROTO_DSTOPTS
        case 43: // IPPROTO_ROUTING
        case 135:// IPPROTO_MH
          info.headerLength = (headerLength + 1) * 8;
          break;
        default:
          isExtHeader = false;
          break;
      }

      if (!isExtHeader || info.dataLength < info.headerLength) {
        break;
      }

      info.protocol = this.packetDataView.getUint8(info.dataOffset);
      info.dataOffset += info.headerLength;
      info.dataLength -= info.headerLength;
    }

    return true;
  }

  /**
   * Handles IPv6 fragmentation header
   * @private
   * @param {Object} info - Packet information object
   * @param {number} headerLength - Length of the header
   * @returns {boolean} True if handling successful, false otherwise
   */
  #handleIPv6FragmentHeader(info, headerLength) {
    if (info.fragment || info.dataLength < headerLength) {
      return false;
    }

    info.fragHeader = this.#readIpv6FragHdr(info.dataOffset);
    info.fragOff = info.fragHeader.getFragOff();
    info.MF = info.fragHeader.getMF();
    info.fragment = true;
    info.headerLength = headerLength;

    return true;
  }

  /**
   * Parses TCP header
   * @private
   * @param {Object} info - Packet information object
   */
  #parseTCPHeader(info) {
    if (info.dataLength < 20) {
      console.warn("IPPROTO_TCP has invalid header length");
      info.protocolHeader = null;
      return;
    }

    info.protocolHeader = this.#readTcpHdr(info.dataOffset);
    
    if (info.protocolHeader.getHdrLength() < 5) {
      console.warn("IPPROTO_TCP has invalid header length");
      info.protocolHeader = null;
      return;
    }

    info.headerLength = info.protocolHeader.getHdrLength() * UINT32_SIZE_BYTES;
    info.headerLength = Math.min(info.headerLength, info.dataLength);
  }

  /**
   * Parses UDP header
   * @private
   * @param {Object} info - Packet information object
   */
  #parseUDPHeader(info) {
    if (info.dataLength < 8) {
      console.warn("IPPROTO_UDP has invalid header length");
      return;
    }

    info.protocolHeader = this.#readUdpHdr(info.dataOffset);
    info.headerLength = 8;
  }

  /**
   * Parses ICMP header
   * @private
   * @param {Object} info - Packet information object
   */
  #parseICMPHeader(info) {
    if (info.dataLength < 8) {
      console.warn("IPPROTO_ICMP has invalid header length");
      return;
    }

    info.protocolHeader = this.#readIcmpHdr(info.dataOffset);
    info.headerLength = 8;
  }
}

module.exports = { HeaderReader, BYTESWAP16 };