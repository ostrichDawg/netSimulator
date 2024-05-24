#pragma once

#include <stdexcept>
#include <iostream>
#include <map>
#include <vector>
#include "pcap.h"

#undef inline

const int ETH_TYPE_POS = 12;
const int IP4_TYPE_POS = 23;
const int IP4_IDENTI_POS = 16;
const int IP4_CHKSUM_POS = 22;
const int IP4_SENDER_POS = 26;
const int IP4_DESTIN_POS = 30;

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

enum class IcmpTypes
{
	ICMP = 0x01,
	REQUEST = 0x08,
	REPLY = 0x00
};

enum class IcmpPositions
{
	TYPE = 48,
	REQUEST = 0x08,
	REPLY = 0x00
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

	inline bool IsArp(const u_char* pkt_data);
	inline bool IsIcmp(const u_char* pkt_data, int pktSize);

	void ProccessIcmp(const u_char* pkt_data, int pktSize);
	void ProccessIcmpRequest(const u_char* pkt_data, int pktSize);

	void ProccessArpRequest(const u_char* pkt_data);
	inline void ProccessArpReply(const u_char* pkt_data);
	void ProccesArp(const u_char* pkt_data);

	void FindAllDevices(pcap_if_t** alldevs);
	void PrintDevicesList(pcap_if_t* alldevs);
	void SelectDevice(pcap_if_t* alldevs);
};

