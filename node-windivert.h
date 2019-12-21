#ifndef WINDIVERT_H_
#define WINDIVERT_H_

#include <napi.h>
#include <iostream>
#include "windivert.h"

#define MAXBUF  0xFFFF

using namespace std;

class WinDivert : public Napi::ObjectWrap<WinDivert> {
	public:
		static WINDIVERT_ADDRESS addr;
		static Napi::Object Init(Napi::Env env, Napi::Object exports);
		WinDivert(const Napi::CallbackInfo& info);
		virtual ~WinDivert() {
					cout << "destroy" << endl;
		}
	private:
		static Napi::FunctionReference constructor;

		Napi::Value open(const Napi::CallbackInfo& info);
		Napi::Value recv(const Napi::CallbackInfo& info);
		Napi::Value close(const Napi::CallbackInfo& info);
		Napi::Value WinDivert::send(const Napi::CallbackInfo& info);
		Napi::Value WinDivert::HelperCalcChecksums(const Napi::CallbackInfo& info);
		
		string filter_;
		Napi::String filter2_;
		HANDLE handle_;
		
		
};



#endif


/*
#include <node.h>
#include <node_object_wrap.h>
#include <string>

namespace windivert {

class WinDivert : public node::ObjectWrap {
 public:
  static void Init(v8::Local<v8::Object> exports);
WINDIVERT_ADDRESS addr;
 private:
  explicit WinDivert(std::string filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
  ~WinDivert();

  HANDLE handle;
  

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void setQueueLength(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void getQueueLength(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void getQueueTime(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void setQueueTime(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void recv(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void send(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void close(const v8::FunctionCallbackInfo<v8::Value>& args);
  static v8::Persistent<v8::Function> constructor;
};

} 
*/


/*

// ...
Napi::Value Exectute(const Napi::CallbackInfo& info) {
 // Retrieve the buffer
 Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
// continue to use the buffer ...
}

// Addon initialization code
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports["execute"] = Napi::Function::New(env, Execute);
  return exports;
}
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
*/