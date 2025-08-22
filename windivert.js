const path = require('path');
let wd;
try {
        const arch = process.arch === 'ia32' ? 'ia32' : 'x64';
        wd = require(path.join(__dirname, 'bin', arch, 'windivert.node'));
} catch (e) {
        // Fallback to a locally built addon
        wd = require('node-gyp-build')(__dirname);
}
wd.decoders = require('./decoders.js');
wd.listen = (filter, cb, handleClose = true) => {
        const handle = new wd.WinDivert(filter, 0, 0, 0);
        handle.open();
        const recvLoop = () => {
                handle.recv((err, data) => {
                        const ret = cb(data.packet, data.addr);
                        if (Buffer.isBuffer(ret)) {
                                handle.HelperCalcChecksums(data, 0);
                                handle.send(data);
                        } else if (ret !== false) {
                                handle.send(data);
                        }
                        recvLoop();
                });
        };
        recvLoop();
        if (handleClose) {
                const exitHandler = (options, err) => {
                        console.log("Exiting");
                        if (err) console.log(err.stack);
                        if (options.exit){handle.close(); process.exit();}
                };
                process.on('exit', exitHandler.bind(null,{cleanup:true}));
                process.on('SIGINT', exitHandler.bind(null, {exit:true}));
                process.on('uncaughtException', exitHandler.bind(null, {exit:true}));
        }
        return handle;
};
module.exports = wd;
