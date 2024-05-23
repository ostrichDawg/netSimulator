#pragma once

#include "pcap.h"
#include <stdexcept>
#include <iostream>

const int PACKET_TYPE_POS = 12;
const uint16_t ARP_PACKET_TYPE = 0x0806;

const int ARP_OPERATION_POS = 20;
const uint16_t ARP_REQUEST = 0x0001;
const uint16_t ARP_REPLY = 0x0002;

//struct ip
//{
//	uint8_t bytes[4];
//};
//
//struct mac
//{
//	uint8_t bytes[6];
//};

class NSimulator
{
public:
	NSimulator() : adhandle{ nullptr }, numberOfDevices{ 0 }
	{}

	~NSimulator() = default;

	void SetDeviceHandler();
	void GetPacketsLoop();

private:
	pcap_t* adhandle;
	int numberOfDevices;

	//std::map<ip, mac> arpTable;

	bool IsARP(const u_char* pkt_data, int pkt_size);

	void ProccesARP(const u_char* pkt_data, int pkt_size);

	void FindAllDevices(pcap_if_t** alldevs);
	void PrintDevicesList(pcap_if_t* alldevs);
	void SelectDevice(pcap_if_t* alldevs);
};

