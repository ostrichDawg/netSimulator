#pragma once

#include <map>

#include "NetInterface.h"
#include "Frame.h"
#include "SafeArpTable.h"

class ArpServer
{
public:
	ArpServer(SafeArpTable& table, const std::map<uint32_t, HostNetConfig>& netConfig) : table{ table }, netConfig { netConfig }, isRunning{ false }
	{}
	~ArpServer();

	void Initialize(const std::string& ip4Addr);
	void Start();
	void Kill();

	MAC GetMacForIP4(uint32_t ip) const;
	void ProccessMissing();

private:
	std::atomic_bool isRunning;
	std::thread arpThread;

	NetInterface dhandler;
	
	SafeArpTable& table;

	// key is a gateway's ip4 address
	const std::map<uint32_t, HostNetConfig>& netConfig;

	void ProccessARP();
	void ProccessRequest(const ArpFrame* frame);
	void ProccessReply(const ArpFrame* frame);

	void SendRequest(uint32_t senderIP, uint32_t targetIP);
};
