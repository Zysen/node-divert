/**
 * @file node-windivert.h
 * @brief Node.js Native Add-on Header for WinDivert
 * 
 * This header file defines the interface between Node.js and the WinDivert driver,
 * providing functionality for packet interception and modification on Windows systems.
 */

#ifndef WINDIVERT_H_
#define WINDIVERT_H_

#define NAPI_VERSION 4
#include <napi.h>
#include <iostream>
#include "windivert.h"
#include <thread>
#include <atomic>
#include <codecvt>

#define MAXBUF  WINDIVERT_MTU_MAX

using namespace std;

/**
 * @class WinDivert
 * @brief Main class for WinDivert functionality in Node.js
 * 
 * This class wraps the WinDivert driver functionality and exposes it to Node.js
 * through N-API. It provides methods for intercepting, modifying, and injecting
 * network packets.
 */
class WinDivert : public Napi::ObjectWrap<WinDivert> {
	public:
		/**
		 * @brief Initializes the WinDivert module
		 * @param env The Node.js environment
		 * @param exports The exports object to attach the module to
		 * @return The modified exports object
		 */
		static Napi::Object Init(Napi::Env env, Napi::Object exports);

		/**
		 * @brief Constructor
		 * @param info Contains filter string and optional layer and flags
		 */
		WinDivert(const Napi::CallbackInfo& info);

		/**
		 * @brief Destructor - Cleans up resources
		 */
		virtual ~WinDivert();

	private:
		/**
		 * @brief Opens the WinDivert handle
		 * @param info Not used
		 * @return Undefined
		 */
		Napi::Value open(const Napi::CallbackInfo& info);

		/**
		 * @brief Starts asynchronous packet reception
		 * @param info Contains callback function
		 * @return Status string
		 */
		Napi::Value recv(const Napi::CallbackInfo& info);

		/**
		 * @brief Closes the WinDivert handle
		 * @param info Not used
		 * @return Boolean indicating success
		 */
		Napi::Value close(const Napi::CallbackInfo& info);

		/**
		 * @brief Sends a packet through WinDivert
		 * @param info Contains packet data and address
		 * @return Boolean indicating success
		 */
		Napi::Value WinDivert::send(const Napi::CallbackInfo& info);

		/**
		 * @brief Calculates packet checksums
		 * @param info Contains packet and flags
		 * @return Object with calculated checksums
		 */
		Napi::Value WinDivert::HelperCalcChecksums(const Napi::CallbackInfo& info);

		/**
		 * @brief Starts the packet receiving thread
		 */
		void StartThread();

		/**
		 * @brief Stops the packet receiving thread
		 */
		void StopThread();

		/**
		 * @brief Main thread function for packet reception
		 */
		void ThreadFunction();
		
		string filter_;                  ///< WinDivert filter string
		UINT32 flags_;                  ///< WinDivert operation flags
		UINT32 layer_;                  ///< WinDivert operation layer
		HANDLE handle_;                 ///< WinDivert handle

		Napi::ThreadSafeFunction tsfn;  ///< Thread-safe function for callbacks
		std::thread recvThread;         ///< Packet receiving thread
		std::atomic<int> closeFlag;     ///< Flag to signal thread closure			
};
#endif