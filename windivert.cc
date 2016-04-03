#include "uv.h"
#include <node.h>
#include <node_buffer.h>
#include "windivert.h"
#include "node-windivert.h"
#include <windows.h>
#include <string>
#include <iostream>

#define MAXBUF  0xFFFF

namespace windivert {
using namespace v8;
using namespace node;
using namespace std;

using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

Persistent<Function> WinDivert::constructor;

void myFree (char * bu, void *hint) {
	
}

void HelperCalcChecksums(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();  
	size_t packetLen = Buffer::Length(args[0]);
	char* packet = Buffer::Data(args[0]);
	UINT res = WinDivertHelperCalcChecksums(packet, (UINT)packetLen, args[1]->IntegerValue());
	args.GetReturnValue().Set(Buffer::New(isolate, packet, packetLen, myFree, NULL).ToLocalChecked());
}

WinDivert::WinDivert(std::string filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags){	// : value_(value) {
	handle = WinDivertOpen(filter.c_str(), layer, priority, flags);
}

WinDivert::~WinDivert() {
	delete handle;
	//delete &addr;
}

void WinDivert::Init(Local<Object> exports) {
  Isolate* isolate = exports->GetIsolate();

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
  tpl->SetClassName(String::NewFromUtf8(isolate, "WinDivert"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "setQueueLength", setQueueLength);
  NODE_SET_PROTOTYPE_METHOD(tpl, "getQueueLength", setQueueLength);
  NODE_SET_PROTOTYPE_METHOD(tpl, "setQueueTime", setQueueLength);
  NODE_SET_PROTOTYPE_METHOD(tpl, "getQueueTime", setQueueLength);
  NODE_SET_PROTOTYPE_METHOD(tpl, "recv", recv);
  NODE_SET_PROTOTYPE_METHOD(tpl, "send", send);
  NODE_SET_PROTOTYPE_METHOD(tpl, "close", close);

  constructor.Reset(isolate, tpl->GetFunction());
  exports->Set(String::NewFromUtf8(isolate, "open"), tpl->GetFunction());
  NODE_SET_METHOD(exports, "HelperCalcChecksums", HelperCalcChecksums);
  //exports->Set(String::NewFromUtf8(isolate, "HelperCalcChecksums"), HelperCalcChecksums);
}

void WinDivert::New(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
	v8::String::Utf8Value param1(args[0]->ToString());
    WINDIVERT_LAYER layer = (WINDIVERT_LAYER)args[1]->IntegerValue();
string filter =string(*param1);
  if (args.IsConstructCall()) {
    // Invoked as constructor: `new WinDivert(...)`
    
    WinDivert* obj = new WinDivert(filter, layer, (INT16)args[2]->IntegerValue(), (INT16)args[3]->IntegerValue());
    obj->Wrap(args.This());
    args.GetReturnValue().Set(args.This());
  } else {
    // Invoked as plain function `WinDivert(...)`, turn into construct call.
    const int argc = 4;
    Local<Value> argv[argc] = { args[0], args[1], args[2], args[3] };
    Local<Function> cons = Local<Function>::New(isolate, constructor);
    args.GetReturnValue().Set(cons->NewInstance(argc, argv));
  }
}

void WinDivert::setQueueLength(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  WinDivert* obj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
  args.GetReturnValue().Set(Boolean::New(isolate, WinDivertSetParam(obj->handle, WINDIVERT_PARAM_QUEUE_LEN, args[1]->IntegerValue())));
}

void WinDivert::getQueueLength(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  WinDivert* obj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
  UINT64 queueLength;
  WinDivertGetParam(obj->handle, WINDIVERT_PARAM_QUEUE_LEN, &queueLength);
  args.GetReturnValue().Set(Number::New(isolate, (double)queueLength));
}

void WinDivert::setQueueTime(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  WinDivert* obj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
  args.GetReturnValue().Set(Boolean::New(isolate, WinDivertSetParam(obj->handle, WINDIVERT_PARAM_QUEUE_TIME, args[1]->IntegerValue())));
}

void WinDivert::getQueueTime(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  WinDivert* obj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
  UINT64 queueLength;
  WinDivertGetParam(obj->handle, WINDIVERT_PARAM_QUEUE_TIME, &queueLength);
  args.GetReturnValue().Set(Number::New(isolate, (double)queueLength));
}

void WinDivert::close(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();  
	WinDivert* obj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
	args.GetReturnValue().Set(Boolean::New(isolate, WinDivertClose(obj->handle)));
}

void WinDivert::send(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();  
	WinDivert* baseObj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
	
    Local<Object> obj = args[0]->ToObject();
    WINDIVERT_ADDRESS addr;
    addr.IfIdx = (UINT32)obj->Get(String::NewFromUtf8(isolate, "address_ifIdx"))->IntegerValue();
    addr.SubIfIdx = (UINT32)obj->Get(String::NewFromUtf8(isolate, "address_subIfIdx"))->IntegerValue();
    addr.Direction = (UINT8)obj->Get(String::NewFromUtf8(isolate, "direction"))->IntegerValue();
    
    size_t packetLen = Buffer::Length(obj->Get(String::NewFromUtf8(isolate, "packet")));
	char* packet = Buffer::Data(obj->Get(String::NewFromUtf8(isolate, "packet")));	

	if(!WinDivertSend(baseObj->handle, packet, (UINT)packetLen, &addr, NULL)){
		DWORD err = GetLastError();		
		args.GetReturnValue().Set(Number::New(isolate, err));
	}
	else{
		args.GetReturnValue().Set(Boolean::New(isolate, true));
	}
}

struct AsyncRecvData {
	HANDLE handle;
	Persistent<Function> callback;
	UINT packetLen;
	char packet[MAXBUF];
	WINDIVERT_ADDRESS addr;
  ~AsyncRecvData() {
  	//free(&handle);
    //free(&packet);
    //free(&packetLen);
    //delete addr;
    callback.Reset();
  }
};

void recvAsync(uv_work_t* req) {
	auto data = reinterpret_cast<AsyncRecvData*>(req->data);
    UINT packetLen;
	if (WinDivertRecv(data->handle, data->packet, sizeof(data->packet), &(data->addr), &packetLen)){
		data->packetLen = packetLen;
	}
	else{
	cout << "Recv Error, Are you running as administrator?" << endl;
	}
};

void afterRecvAsync(uv_work_t* req, int status) {	
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	auto data = reinterpret_cast<AsyncRecvData*>(req->data);
	WINDIVERT_ADDRESS addr = data->addr;

	Local<Object> obj = Object::New(isolate);	
    obj->Set(String::NewFromUtf8(isolate, "packet"), Buffer::New(isolate, (char*)data->packet, (size_t)data->packetLen, myFree, NULL).ToLocalChecked());
    obj->Set(String::NewFromUtf8(isolate, "address_ifIdx"), Number::New(isolate, addr.IfIdx));
	obj->Set(String::NewFromUtf8(isolate, "address_subIfIdx"), Number::New(isolate, addr.SubIfIdx));
	obj->Set(String::NewFromUtf8(isolate, "direction"), Number::New(isolate, addr.Direction));
	obj->Set(String::NewFromUtf8(isolate, "length"), Number::New(isolate, data->packetLen)); 
	Local<Value> argv[1] = {obj};
	Local<Function> callback = Local<Function>::New(isolate, data->callback);
	callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
	req->data = 0;
	delete data;
	
}

void WinDivert::recv(const FunctionCallbackInfo<Value>& args) {
	uv_work_t* req = new uv_work_t;
	AsyncRecvData* data = new AsyncRecvData;
	
	Isolate* isolate = args.GetIsolate(); 
	WinDivert* obj = ObjectWrap::Unwrap<WinDivert>(args.Holder());
	
	req->data = data;
	data->handle = obj->handle;
	
	Local<Function> callback = Local<Function>::Cast(args[0]);
    data->callback.Reset(isolate, callback);
	
	//Local<Function> cb = Local<Function>::Cast(args[0]);
	//data->callback = v8::Persistent<v8::Function>::Cast(cb);
	uv_queue_work(uv_default_loop(), req, recvAsync, afterRecvAsync);
}

NODE_MODULE(addon, WinDivert::Init)

}  // namespace demo