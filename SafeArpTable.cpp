#include "SafeArpTable.h"

MAC SafeArpTable::GetMAC(uint32_t ip) const
{
	std::shared_lock<std::shared_mutex> lock(arpTableMutex);

	std::map<uint32_t, MAC>::const_iterator iter = arpTable.find(ip);
	if (iter == arpTable.end())
	{
		in_addr addr;
		addr.s_addr = ip;
		throw std::runtime_error("ARP record for " + std::string{ inet_ntoa(addr) } + " not found!");
	}

	return iter->second;
}

void SafeArpTable::PutMACFor(uint32_t ip, const MAC& mac)
{
	std::unique_lock<std::shared_mutex> lock(arpTableMutex);
	arpTable[ip] = mac;
}

void SafeArpTable::PutMissing(uint32_t targetIP, uint32_t senderIP)
{
	std::lock_guard<std::mutex> lock(missingArpMutex);
	missingArp[targetIP] = senderIP;
}

MissingArpRecord SafeArpTable::PopMissingArp()
{
	std::lock_guard<std::mutex> lock(missingArpMutex);

	MissingArpRecord result{ 0, 0 };

	if (missingArp.empty() == true)
	{
		return result;
	}

	result.targetIP = missingArp.begin()->first;
	result.senderIP = missingArp.begin()->second;

	missingArp.erase(result.targetIP);

	return result;
}
