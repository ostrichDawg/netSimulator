#pragma once

#include <stdexcept>
#include <iostream>
#include <vector>
#include <map>

#include "Frame.h"

#include "pcap.h"

#undef inline

struct MAC
{
	uint8_t bytes[6];
};

struct NetCFG
{
	uint32_t ip;
	MAC mac;
};

class NSimulator
{
public:
	NSimulator() : adhandle{ nullptr }, numberOfDevices{ 0 }
	{
		uint8_t bytes[6] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb };
		
		netFor[0x0201a8c0].ip = 0x0101a8c0;
		netFor[0x0201a8c0].mac = *(MAC*)(bytes);

		netFor[0xae07000a].ip = 0xbb07000a;
		netFor[0x0201a8c0].mac = *(MAC*)(bytes);
	}

	~NSimulator() = default;

	void SetDeviceHandler();
	void GetPacketsLoop();

private:
	pcap_t* adhandle;
	int numberOfDevices;

	std::map<uint32_t, NetCFG> netFor;
	std::map<uint32_t, MAC> arpTable;

	inline bool IsARP(const void* pkt_data);
	inline bool IsICMP(const void* pkt_data);

	void ProccessICMP(const void* pkt_data, int pktSize);
	void ProccessICMPRequest(const void* pkt_data, int pktSize);
	inline void ProccessICMPReply(const void* pkt_data, int pktSize);

	void ProccesARP(const void* pkt_data);
	void ProccessArpRequest(const void* pkt_data);
	inline void ProccessArpReply(const void* pkt_data);

	void FindAllDevices(pcap_if_t** alldevs);
	void PrintDevicesList(pcap_if_t* alldevs);
	void SelectDevice(pcap_if_t* alldevs);
};

