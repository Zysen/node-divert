/**
 * @module windivert
 * @description A Node.js binding for WinDivert driver to capture and modify network packets
 */

const wd = require('bindings')('WinDivert');
const { HeaderReader, BYTESWAP16 } = require('./decoders.js');

/**
 * @constant {Object} FLAGS
 * @description WinDivert flags for controlling packet interception
 * @property {number} DEFAULT - Default flag (0x0000)
 * @property {number} SNIFF - Sniffing mode flag (0x0001)
 * @property {number} DROP - Drop packets flag (0x0002)
 * @property {number} RECV_ONLY - Receive only mode (0x0004)
 * @property {number} READ_ONLY - Same as RECV_ONLY (0x0004)
 * @property {number} SEND_ONLY - Send only mode (0x0008)
 * @property {number} WRITE_ONLY - Same as SEND_ONLY (0x0008)
 * @property {number} NO_INSTALL - No install flag (0x0010)
 * @property {number} FRAGMENTS - Handle fragments flag (0x0020)
 */
const FLAGS = Object.freeze({
	DEFAULT: 0x0000,
	SNIFF: 0x0001,
	DROP: 0x0002,
	RECV_ONLY: 0x0004,
	READ_ONLY: 0x0004,  // Same as RECV_ONLY
	SEND_ONLY: 0x0008,
	WRITE_ONLY: 0x0008, // Same as SEND_ONLY
	NO_INSTALL: 0x0010,
	FRAGMENTS: 0x0020
});

/**
 * @constant {Object} PROTOCOLS
 * @description Common network protocols
 * @property {number} TCP - TCP protocol (6)
 * @property {number} UDP - UDP protocol (17)
 * @property {number} ICMP - ICMP protocol (1)
 * @property {number} ICMPV6 - ICMPv6 protocol (58)
 */
const PROTOCOLS = Object.freeze({
	TCP: 6,
	UDP: 17,
	ICMP: 1,
	ICMPV6: 58,

});

/**
 * @constant {Object} LAYERS
 * @description WinDivert layer constants
 * @property {number} NETWORK - Network layer
 * @property {number} NETWORK_FORWARD - Network forward layer
 * @property {number} FLOW - Flow layer
 * @property {number} SOCKET - Socket layer
 * @property {number} REFLECT - Reflect layer
 */
const LAYERS = Object.freeze({
	NETWORK: 0,
	NETWORK_FORWARD: 1,
	FLOW: 2,
	SOCKET: 3,
	REFLECT: 4
});

/**
 * @async
 * @function checkAdmin
 * @description Checks if the application is running with administrator privileges
 * @throws {Error} Throws an error if not running as administrator
 */
async function checkAdmin() {
	await import('is-admin').then(async (isAdmin) => {
		if (!await isAdmin.default()) {
			throw new Error('You must run this application as an administrator.');
		}
	});
}

/**
 * @async
 * @function createWindivert
 * @description Creates a new WinDivert handle
 * @param {string} filter - WinDivert filter string
 * @param {number} layer - WinDivert layer
 * @param {number} flag - WinDivert flags
 * @returns {Promise<Object>} WinDivert handle
 * @throws {Error} Throws an error if not running as administrator
 */
async function createWindivert(filter, layer, flag) {
	await checkAdmin();
	return new wd.WinDivert(filter, layer, flag);
};

/**
 * @function addReceiveListener
 * @description Adds a packet receive listener to a WinDivert handle
 * @param {Object} handle - WinDivert handle
 * @param {Function} callback - Callback function to process packets
 * @param {Buffer} callback.packet - The received packet
 * @param {Object} callback.addr - The packet address information
 * @returns {Buffer|undefined} Modified packet or undefined to use original packet
 */
function addReceiveListener(handle, callback) {
	try {
		handle.recv(function (packet, addr) {
			const newPacket = callback(packet, addr);
			if (Buffer.isBuffer(newPacket)) {
				try {
					handle.HelperCalcChecksums(newPacket, 0);
					handle.send({ packet: newPacket, addr })
				} catch (error) {
					console.error("Recv Error:", error);
				}
			} else if (newPacket === undefined) {
				handle.send({ packet, addr });
			}
		});
	} catch (error) {
		console.error(error);
	}
};

/**
 * @exports windivert
 */
module.exports = {
	FLAGS,
	LAYERS,
	PROTOCOLS,
	createWindivert,
	addReceiveListener,
	HeaderReader,
	BYTESWAP16
};
