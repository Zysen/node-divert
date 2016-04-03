WinDivert 1.1: NodeJS Bindings
====================================

1. Introduction
---------------
This module provides NodeJS bindings for the WinDivert project. WinDivert provides packet sniffing, modification, injection and blocking for windows.
WinDivert: https://reqrypt.org/windivert.html

See the windivert readme: https://github.com/basil00/Divert/blob/master/README

2. Installation
---------------
	1) Download WinDivert-1.1.8-MSVC.zip from https://reqrypt.org/windivert.html
	2) Find WinDivert32.sys and WinDivert64.sys and put them in your project directory.
	3) Find WinDivert.dll and put that in your project directory. Choose one from the amd64 or x86 directory depending on your build options. (Usually x86)
	4) Find WinDivert.lib and put that in your project directory

3. Examples
---------------

	//Print Packet
	var wd = require("windivert");
	wd.listen("udp.DstPort==41234 or udp.SrcPort==41234", function(data, inbound){
		console.log(data.toString());
	});

	//Block Packet	
	var wd = require("windivert");
	wd.listen("udp.DstPort==41234 or udp.SrcPort==41234", function(data, inbound){
		console.log("BLOCKED", data.toString());
		return false;
	});

	//Modify Packet
	require("buffertools").extend();
	var wd = require("windivert");
	wd.listen("udp.DstPort==41234 or udp.SrcPort==41234", function(data, inbound){	//inbound is bool
		var d = new Buffer(data);
		console.log(data.toString());
		var i = d.indexOf(new Buffer("BOB"));
		if(i>=0){
			d.writeUInt8("S".charCodeAt(0), i++);
			d.writeUInt8("A".charCodeAt(1), i++);
			d.writeUInt8("M".charCodeAt(2), i++);
		}
		return wd.HelperCalcChecksums(d, 0);
	});
