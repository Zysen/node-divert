#ifndef WINDIVERT_H_
#define WINDIVERT_H_

#include "./windivertlib/include/windivert.h"
#include <iostream>
#include <napi.h>

#define MAXBUF 0xFFFF

using namespace std;

class WinDivert : public Napi::ObjectWrap<WinDivert>
{
public:
	static WINDIVERT_ADDRESS addr;
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	WinDivert(const Napi::CallbackInfo &info);
	virtual ~WinDivert()
	{
		cout << "destroy" << endl;
	}

private:
	static Napi::FunctionReference constructor;

	Napi::Value open(const Napi::CallbackInfo &info);
	Napi::Value recv(const Napi::CallbackInfo &info);
	Napi::Value close(const Napi::CallbackInfo &info);
	Napi::Value send(const Napi::CallbackInfo &info);
	Napi::Value HelperCalcChecksums(const Napi::CallbackInfo &info);

	string filter_;
	WINDIVERT_LAYER layer_;
	INT16 priority_;
	UINT64 flags_;
	HANDLE handle_;
};

#endif
