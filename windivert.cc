#include "node-windivert.h"

class RecvWorker : public Napi::AsyncWorker
{
public:
	RecvWorker(Napi::Function &callback, HANDLE hndl) : Napi::AsyncWorker(callback), handle(hndl) {}
	~RecvWorker() {}
	void Execute()
	{
		// cout << "WinDivertRecv" << endl;
		if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr))
		{
			Napi::TypeError::New(Env(), "Exception during WinDivertRecv\nAre you running as administrator?").ThrowAsJavaScriptException();
		}
		// cout << "WinDivertRecv packetLen " << packetLen << " Packet=" << packet << endl;
	}
	void OnOK()
	{

		/*
	typedef struct
	{
		INT64  Timestamp;                 Packet's timestamp.
		UINT32 Layer:8;                      Packet's layer.
		UINT32 Event:8;                      Packet event.
		UINT32 Sniffed:1;                   Packet was sniffed?
		UINT32 Outbound:1;                  Packet is outound?
		UINT32 Loopback:1;                   Packet is loopback?
		UINT32 Impostor:1;                   Packet is impostor?
		UINT32 IPv6:1;                      Packet is IPv6? *
		UINT32 IPChecksum:1;                Packet has valid IPv4 checksum?
		UINT32 TCPChecksum:1;                Packet has valid TCP checksum?
		UINT32 UDPChecksum:1;                Packet has valid UDP checksum?
		UINT32 Reserved1:8;
		UINT32 Reserved2;
		union
		{
			WINDIVERT_DATA_NETWORK Network;  Network layer data.
			WINDIVERT_DATA_FLOW Flow;       Flow layer data.
			WINDIVERT_DATA_SOCKET Socket;    Socket layer data.
			WINDIVERT_DATA_REFLECT Reflect;  Reflect layer data.
			UINT8 Reserved3[64];
		};
	} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

	typedef struct
	{
		UINT32 IfIdx;                        Packet's interface index.
		UINT32 SubIfIdx;                     Packet's sub-interface index.
	} WINDIVERT_DATA_NETWORK, *PWINDIVERT_DATA_NETWORK;


	typedef struct
	{
		UINT64 EndpointId;                   Endpoint ID.
		UINT64 ParentEndpointId;             Parent endpoint ID.
		UINT32 ProcessId;                    Process ID.
		UINT32 LocalAddr[4];                 Local address.
		UINT32 RemoteAddr[4];                Remote address.
		UINT16 LocalPort;                    Local port.
		UINT16 RemotePort;                   Remote port.
		UINT8  Protocol;                     Protocol.
	} WINDIVERT_DATA_FLOW, *PWINDIVERT_DATA_FLOW;

	 WinDivert SOCKET layer data.

	typedef struct
	{
		UINT64 EndpointId;                   Endpoint ID.
		UINT64 ParentEndpointId;             Parent Endpoint ID.
		UINT32 ProcessId;                    Process ID.
		UINT32 LocalAddr[4];                 Local address.
		UINT32 RemoteAddr[4];                Remote address.
		UINT16 LocalPort;                    Local port.
		UINT16 RemotePort;                   Remote port.
		UINT8  Protocol;                     Protocol.
	} WINDIVERT_DATA_SOCKET, *PWINDIVERT_DATA_SOCKET;


	 WinDivert REFLECTION layer data.

	typedef struct
	{
		INT64  Timestamp;                    Handle open time.
		UINT32 ProcessId;                    Handle process ID.
		WINDIVERT_LAYER Layer;               Handle layer.
		UINT64 Flags;                        Handle flags.
		INT16  Priority;                     Handle priority.
	} WINDIVERT_DATA_REFLECT, *PWINDIVERT_DATA_REFLECT;
	*/

		Napi::Env env = Env();

		Napi::Object obj = Napi::Object::New(env);
		obj.Set(Napi::String::New(env, "packet"), Napi::Buffer<char>::New(Env(), packet, (size_t)packetLen));
		Napi::Object addrJs = Napi::Object::New(env);
		addrJs.Set(Napi::String::New(env, "Timestamp"), addr.Timestamp); // TODO Change this to bigint && put a number
		addrJs.Set(Napi::String::New(env, "Layer"), addr.Layer);
		addrJs.Set(Napi::String::New(env, "Event"), addr.Event);
		addrJs.Set(Napi::String::New(env, "Sniffed"), addr.Sniffed);
		addrJs.Set(Napi::String::New(env, "Outbound"), addr.Outbound);
		addrJs.Set(Napi::String::New(env, "Loopback"), addr.Loopback);
		addrJs.Set(Napi::String::New(env, "Impostor"), addr.Impostor);
		addrJs.Set(Napi::String::New(env, "IPv6"), addr.IPv6);
		addrJs.Set(Napi::String::New(env, "IPChecksum"), addr.IPChecksum);
		addrJs.Set(Napi::String::New(env, "TCPChecksum"), addr.TCPChecksum);
		addrJs.Set(Napi::String::New(env, "UDPChecksum"), addr.UDPChecksum);
		addrJs.Set(Napi::String::New(env, "Reserved1"), addr.Reserved1);
		addrJs.Set(Napi::String::New(env, "Reserved2"), addr.Reserved2);

		Napi::Object networkJS = Napi::Object::New(env);
		networkJS.Set(Napi::String::New(env, "IfIdx"), addr.Network.IfIdx);
		networkJS.Set(Napi::String::New(env, "SubIfIdx"), addr.Network.SubIfIdx);
		addrJs.Set(Napi::String::New(env, "Network"), networkJS);

		obj.Set(Napi::String::New(env, "addr"), addrJs);
		// Napi::HandleScope scope(Env());
		Callback().Call({Env().Undefined(), obj});
	}

private:
	HANDLE handle;
	UINT packetLen;
	char packet[MAXBUF];
	WINDIVERT_ADDRESS addr;
};

Napi::FunctionReference WinDivert::constructor;
Napi::Object WinDivert::Init(Napi::Env env, Napi::Object exports)
{
	Napi::HandleScope scope(env);
	Napi::Function func = DefineClass(env, "WinDivert", {InstanceMethod("open", &WinDivert::open), InstanceMethod("HelperCalcChecksums", &WinDivert::HelperCalcChecksums), InstanceMethod("recv", &WinDivert::recv), InstanceMethod("send", &WinDivert::send), InstanceMethod("close", &WinDivert::close)});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("WinDivert", func);
	return exports;
}

WinDivert::WinDivert(const Napi::CallbackInfo &info) : Napi::ObjectWrap<WinDivert>(info)
{
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);
	int argc = info.Length();
	if (argc <= 0 || !info[0].IsString())
	{
		Napi::TypeError::New(env, "String filter expected").ThrowAsJavaScriptException();
		return;
	}
	filter_ = info[0].As<Napi::String>().Utf8Value();
	layer_ = (WINDIVERT_LAYER)info[1].As<Napi::Number>().Int32Value();
	priority_ = info[2].As<Napi::Number>().Int32Value();
	flags_ = info[3].As<Napi::Number>().Int64Value();
}

Napi::Value WinDivert::recv(const Napi::CallbackInfo &info)
{
	// cout << "recv" << endl;
	Napi::Function callback = info[0].As<Napi::Function>();
	RecvWorker *recvWorker = new RecvWorker(callback, this->handle_);
	recvWorker->Queue();
	return info.Env().Undefined();
}

Napi::Value WinDivert::open(const Napi::CallbackInfo &info)
{
	this->handle_ = WinDivertOpen(filter_.c_str(), layer_, priority_, flags_); // Todo pass these args through , layer, priority, flags   filter_.c_str()
	return info.Env().Undefined();
}

Napi::Value WinDivert::HelperCalcChecksums(const Napi::CallbackInfo &info)
{
	WINDIVERT_ADDRESS addr;
	int argc = info.Length();
	if (argc <= 1 || !info[0].IsObject() || !info[1].IsNumber())
	{
		Napi::TypeError::New(info.Env(), "Object expected").ThrowAsJavaScriptException();
		return info.Env().Undefined();
	}
	Napi::Object packetData = info[0].As<Napi::Object>();
	Napi::Buffer<char> packet = packetData.Get("packet").As<Napi::Buffer<char>>();
	return Napi::Boolean::New(info.Env(), WinDivertHelperCalcChecksums(packet.Data(), packet.Length(), &addr, info[1].As<Napi::Number>().Uint32Value()));
}

Napi::Value WinDivert::send(const Napi::CallbackInfo &info)
{
	WINDIVERT_ADDRESS addr;
	WINDIVERT_DATA_NETWORK network;
	int argc = info.Length();
	if (argc <= 0 || !info[0].IsObject())
	{
		Napi::TypeError::New(info.Env(), "Object expected").ThrowAsJavaScriptException();
		return info.Env().Undefined();
	}

	Napi::Object packetData = info[0].As<Napi::Object>();
	Napi::Buffer<char> packet = packetData.Get("packet").As<Napi::Buffer<char>>();
	Napi::Object addrJS = packetData.Get("addr").As<Napi::Object>();
	Napi::Object networkJS = addrJS.Get("Network").As<Napi::Object>();
	addr.Timestamp = addrJS.Get("Timestamp").As<Napi::Number>().Int64Value();
	addr.Layer = addrJS.Get("Layer").As<Napi::Number>().Uint32Value();
	addr.Event = addrJS.Get("Event").As<Napi::Number>().Uint32Value();
	addr.Sniffed = addrJS.Get("Sniffed").As<Napi::Number>().Uint32Value();
	addr.Outbound = addrJS.Get("Outbound").As<Napi::Number>().Uint32Value();
	addr.Loopback = addrJS.Get("Loopback").As<Napi::Number>().Uint32Value();
	addr.Impostor = addrJS.Get("Impostor").As<Napi::Number>().Uint32Value();
	addr.IPv6 = addrJS.Get("IPv6").As<Napi::Number>().Uint32Value();
	addr.IPChecksum = addrJS.Get("IPChecksum").As<Napi::Number>().Uint32Value();
	addr.TCPChecksum = addrJS.Get("TCPChecksum").As<Napi::Number>().Uint32Value();
	addr.UDPChecksum = addrJS.Get("UDPChecksum").As<Napi::Number>().Uint32Value();
	addr.Reserved1 = addrJS.Get("Reserved1").As<Napi::Number>().Uint32Value();
	addr.Reserved2 = addrJS.Get("Reserved2").As<Napi::Number>().Uint32Value();
	network.IfIdx = networkJS.Get("IfIdx").As<Napi::Number>().Uint32Value();
	network.SubIfIdx = networkJS.Get("SubIfIdx").As<Napi::Number>().Uint32Value();
	addr.Network = network;

	UINT pSendLen;
	return Napi::Boolean::New(info.Env(), WinDivertSend(this->handle_, packet.Data(), packet.Length(), &pSendLen, &addr));
}

Napi::Value WinDivert::close(const Napi::CallbackInfo &info)
{
	return Napi::Boolean::New(info.Env(), WinDivertClose(this->handle_));
}

Napi::Object InitAll(Napi::Env env, Napi::Object exports)
{
	return WinDivert::Init(env, exports);
}
NODE_API_MODULE(addon, InitAll)