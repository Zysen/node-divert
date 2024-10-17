node-windivert: NodeJS bindings for WinDivert
====================================

1. Introduction
---------------
This module provides NodeJS bindings for the WinDivert project. WinDivert provides packet sniffing, modification, injection and blocking for windows.
WinDivert: https://reqrypt.org/windivert.html

See the windivert readme: https://github.com/basil00/Divert/blob/master/README

2. Usage
---------------
	npm install windivert
	
	var wd = require("windivert");
	wd.listen("tcp.DstPort==80 or tcp.SrcPort==80", function(data, inbound){
		console.log("HTTP packet with length", data.length);
	});
	
3. Other Examples
---------------

	//Block Packet	
	var wd = require("windivert");
	wd.listen("tcp.DstPort==80 or tcp.SrcPort==80", function(data, inbound){
		console.log("BLOCKED HTTP packet with length", data.length);
		return false;
	});

	//Modify Packet
	require("buffertools").extend();
	var wd = require("windivert");
	wd.listen("tcp.DstPort==80 or tcp.SrcPort==80", function(data, inbound){	//inbound is bool
		var d = new Buffer(data);
		console.log(data.length);
		var i = d.indexOf(new Buffer("BOB"));
		if(i>=0){
			d.writeUInt8("S".charCodeAt(0), i++);
			d.writeUInt8("A".charCodeAt(0), i++);
			d.writeUInt8("M".charCodeAt(0), i++);
		}
		return wd.HelperCalcChecksums(d, 0);
	});
	
4. Building
---------------
	1) Make sure node-gyp is installed and working. Instructions are here: https://github.com/nodejs/node-gyp
	2) Download WinDivert Version 2.2.2 build from https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip and extract its contents into the folder `windivertlib`. 
	3) node-gyp clean configure build
	4) Windivert will automatically use the custom built binary from build/Release if it exists, instead of the precompiled binaries in ./bin
	