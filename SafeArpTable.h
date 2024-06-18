#pragma once

#include <shared_mutex>
#include <map>
#include "Frame.h"
#include <WinSock2.h>

struct MissingArpRecord
{
	uint32_t targetIP;
	uint32_t senderIP;
};

class SafeArpTable
{
public:
	SafeArpTable() = default;
	~SafeArpTable() = default;

	SafeArpTable(SafeArpTable&) = delete;
	SafeArpTable(SafeArpTable&&) = delete;

	MAC GetMAC(uint32_t ip) const;
	void PutMACFor(uint32_t ip, const MAC& mac);

	void PutMissing(uint32_t requiredIp4, uint32_t forIp4);
	MissingArpRecord PopMissingArp();

private:
	mutable std::shared_mutex arpTableMutex;
	std::map<uint32_t, MAC> arpTable;

	mutable std::mutex missingArpMutex;
	// key - target ip4 address
	// value - sender ip4 address
	std::map<uint32_t, uint32_t> missingArp;
};
