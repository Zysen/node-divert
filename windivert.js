var wd = require(__dirname+'/build/Release/windivert');
wd.decoders = require('./decoders.js');

wd.listen = function(filter, cb, handleClose){
	handleClose = handleClose || true;
	var handle = wd.open(filter, 0, 0, 0);
	(function recvLoop(){
		handle.recv(function(data){
			data.packet = new Buffer(data.packet);
			var ret = cb(data.packet, data.direction===1?true:false, data);
			if(Buffer.isBuffer(ret)){
				data.packet = ret;
				//console.log("Sending a BUFFER!", ret.toString());
				handle.send(data);
			}
			else if(ret!==false){
				//console.log("Sending Original");
				handle.send(data);
			}
			recvLoop();
		});	
	}());	
	if(handleClose){
		function exitHandler(options, err) {
			console.log("Exiting");
		    if (err) console.log(err.stack);
		    if (options.exit){handle.close(); process.exit();}
		}
		process.on('exit', exitHandler.bind(null,{cleanup:true}));
		process.on('SIGINT', exitHandler.bind(null, {exit:true}));
		process.on('uncaughtException', exitHandler.bind(null, {exit:true}));
	}
	return handle;
};
module.exports = wd;
