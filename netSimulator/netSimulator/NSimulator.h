#pragma once

#include <stdexcept>
#include <iostream>
#include <map>

#include "pcap.h"

#undef inline

const int PACKET_TYPE_POS = 12;

enum class ArpTypes
{
	ARP = 0x0608,
	REQUEST = 0x0100,
	REPLY = 0x0200
};

enum class ArpPositions
{
	OPERATION = 20,
	SENDER_MAC = 22,
	SENDER_IP = 28,
	TARGET_MAC = 32,
	TARGET_IP = 38
};

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
	}

	~NSimulator() = default;

	void SetDeviceHandler();
	void GetPacketsLoop();

private:
	pcap_t* adhandle;
	int numberOfDevices;

	std::map<uint32_t, NetCFG> netFor;
	std::map<uint32_t, MAC> arpTable;

	inline bool IsARP(const u_char* pkt_data);
	inline bool IsICMP(const u_char* pkt_data, int pktSize);

	void ProccessICMP(const u_char* pkt_data, int pktSize);

	void ProccessArpRequest(const u_char* pkt_data);
	inline void ProccessArpReply(const u_char* pkt_data);
	void ProccesARP(const u_char* pkt_data);

	void FindAllDevices(pcap_if_t** alldevs);
	void PrintDevicesList(pcap_if_t* alldevs);
	void SelectDevice(pcap_if_t* alldevs);
};

