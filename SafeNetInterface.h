#pragma once

#include <iostream>
#include <stdexcept>
#include <mutex>

#include "pcap.h"

#undef inline

class SafeNetInterface
{
public:
	SafeNetInterface() : adhandle{ nullptr }, numberOfDevices{ 0 }
	{}

	~SafeNetInterface() = default;

	void SelectInterfaceByIP4(const std::string& ip4Addr, const std::string& filterString);

	void SendPacket(const void* pkt_data, size_t pkt_size);
	int GetPacket(pcap_pkthdr** header, const u_char** pkt_data);

private:
	std::mutex mutex;
	pcap_t* adhandle;
	int numberOfDevices;

	void FindAllDevices(pcap_if_t** alldevs);

	void SetDeviceByIP4(const std::string& ip4Addr, pcap_if_t* alldevs, const std::string& filterString);
	void SetFilter(pcap_if_t* device, const std::string& filterString);
};