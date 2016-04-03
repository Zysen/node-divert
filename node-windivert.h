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