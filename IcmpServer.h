#pragma once

#include <vector>
#include <chrono>
#include "Frame.h"
#include "NetInterface.h"
#include "SafeArpTable.h"
#include "InetProto.h"

class IcmpServer
{
public:
	IcmpServer(SafeArpTable& table, const std::map<uint32_t, HostNetConfig>& netConfig): arpTable{ table }, netConfig{ netConfig }, isRunning{ false }
	{}

	~IcmpServer();

	void Initialize(const std::string& ip4Addr);
	void Start();
	void Kill();

private:
	std::atomic_bool isRunning;

	SafeArpTable& arpTable;

	// key is a host's ip4 address
	const std::map<uint32_t, HostNetConfig>& netConfig;

	// key - icmp seqnum
	// pair.first - sender ip4
	// pair.second - receiver ip4
	std::map<uint16_t, std::pair<uint32_t, uint32_t>> noReplyStore;
	
	// mutex for access to noReplyStore
	std::mutex noReplyMutex;

	std::thread senderThread;
	std::thread receiverThread;
	
	NetInterface senderIf;
	NetInterface receiverIf;

	void StartSender();
	void StartReceiver();

	void SendICMPRequestFromTo(const HostNetConfig& senderData, uint32_t receiverIP, std::vector<uint8_t>& requestRAW, uint16_t seqNum);

	void ProccessICMPRequest(const IcmpFrame* frame, int pktSize);
	void ProccessICMPReply(const IcmpFrame* frame, int pktSize);

	void ProccessNoReplys();
};
