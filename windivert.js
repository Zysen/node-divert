var wd = require('bindings')('WinDivert');
wd.decoders = require('./decoders.js');
wd.listen = function (filter, cb, handleClose) {
	handleClose = handleClose || true;
	var handle = new wd.WinDivert(filter, 0, 0, 0);
	handle.open();
	(function recvLoop() {
		handle.recv(function (err, data) {
			var ret = cb(data.packet, data.addr);
			if (Buffer.isBuffer(ret)) {
				handle.HelperCalcChecksums(data, 0);
				handle.send(data);
			}
			else if (ret !== false) {
				handle.send(data);
			}
			recvLoop();
		});
	}());
	if (handleClose) {
		function exitHandler(options, err) {
			console.log("Exiting");
			if (err) console.log(err.stack);
			if (options.exit) { handle.close(); process.exit(); }
		}
		process.on('exit', exitHandler.bind(null, { cleanup: true }));
		process.on('SIGINT', exitHandler.bind(null, { exit: true }));
		process.on('uncaughtException', exitHandler.bind(null, { exit: true }));
	}
	return handle;
};
module.exports = wd;
