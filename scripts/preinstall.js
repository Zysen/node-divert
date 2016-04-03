var fs = require("fs");

var x64 = process.arch==="x64";
var sysName = "WinDivert"+(x64?"64":"32")+".sys";

if(fs.existsSync("../../WinDivert.lib")){
	fs.createReadStream("../../WinDivert.lib").pipe(fs.createWriteStream("WinDivert.lib"));
}

if(fs.existsSync("../../WinDivert.dll")){
	fs.createReadStream("../../WinDivert.dll").pipe(fs.createWriteStream("WinDivert.dll"));
}

if(fs.existsSync("../../"+sysName)){
	fs.createReadStream("../../"+sysName).pipe(fs.createWriteStream(sysName));
}

var libExists = fs.existsSync("WinDivert.lib");
var dllExists = fs.existsSync("WinDivert.dll");
var sysExists = fs.existsSync(sysName);

if((libExists && dllExists && sysExists)===false){
	console.error("Missing Dependencies");
	console.log("Please get the missing files from http://reqrypt.org/download/WinDivert-1.1.8-WDDK.zip or by building the git repository https://github.com/basil00/Divert\nAnd put them in your project directory");
	console.log("WinDivert.lib", libExists?"FOUND":"MISSING");
	console.log("WinDivert.dll", dllExists?"FOUND":"MISSING");
	console.log(sysName, sysExists?"FOUND":"MISSING");	
	console.log("");
	process.exit(1);	
}