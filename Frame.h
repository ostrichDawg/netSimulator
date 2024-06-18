#pragma once
#include <cstdint>

#pragma pack(push, 1)

struct MAC
{
	uint8_t bytes[6];
};

struct HostNetConfig
{
	uint32_t ip;
	uint32_t gateway;
	MAC mac;
};

enum class EthTypes
{
	ARP = 0x0608,
	IP4 = 0x0008
};

enum class IP4Types
{
	ICMP = 0x01,
	UDP = 0x11
};

enum class ArpTypes
{
	REQUEST = 0x0100,
	REPLY = 0x0200
};

enum class IcmpTypes
{
	REQUEST = 0x08,
	REPLY = 0x00
};

struct EthHeader
{
	MAC dst;
	MAC src;
	uint16_t proto;
};

struct Ip4Header
{
	uint8_t v_l;
	uint8_t difSer;
	uint16_t totalLen;
	uint16_t id;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t headerCSum;
	uint32_t src;
	uint32_t dst;
};

struct IcmpHeader
{
	uint8_t type;
	uint8_t code;
	uint16_t checkSum;
	uint16_t id;
	uint16_t seqNum;
};

struct Ip4Frame
{
	EthHeader eth;	
	Ip4Header ip4;
};

struct IcmpFrame
{
	EthHeader eth;
	Ip4Header ip4;

	IcmpHeader icmp;
};

struct ArpFrame
{
	EthHeader eth;

	uint16_t hardware{ 0x0100 };
	uint16_t protocol{ 0x0008 };
	uint8_t hardwareSize{ 0x06 };
	uint8_t protocolSize{ 0x04 };
	uint16_t opcode{ (uint16_t)ArpTypes::REPLY };
	MAC senderMAC;
	uint32_t senderIP{ 0x00000000 };
	MAC targetMAC;
	uint32_t targetIP{ 0x00000000 };
};

#pragma pack(pop)