#pragma once

#include <cstdint>

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
	char dst[6];
	char src[6];
	uint16_t proto;
};

struct Ip4Header
{
	uint8_t versionLen;
	uint8_t difSer;
	uint16_t totalLen;
	uint16_t identification;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t headerCSum;
	uint32_t srcIP;
	uint32_t dstIP;
};

struct IcmpHeader
{
	uint8_t type;
	uint8_t code;
	uint16_t checkSum;
	uint16_t identifier;
	uint16_t seqNum;
};

struct Ip4Frame
{
	//EthHeader eth;
	char dst[6];
	char src[6];
	uint16_t proto;
	
	//Ip4Header ipHeader;
	uint8_t versionLen;
	uint8_t difSer;
	uint16_t totalLen;
	uint16_t identification;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t headerCSum;
	uint32_t srcIP;
	uint32_t dstIP;
};

struct IcmpFrame
{
	char dst[6];
	char src[6];
	uint16_t proto;
	
	uint8_t ip4HeaderLen : 4;
	uint8_t version : 4;
	uint8_t difSer;
	uint16_t totalLen;
	uint16_t identification;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t headerCSum;
	uint8_t srcIP[4];
	uint8_t dstIP[4];

	uint8_t type;
	uint8_t code;
	uint16_t checkSum;
	uint16_t identifier;
	uint16_t seqNum;
};

struct ArpFrame
{
	char dst[6];
	char src[6];
	uint16_t proto;

	uint16_t hardware;
	uint16_t protocol;
	uint8_t hardwareSize;
	uint8_t protocolSize;
	uint16_t opcode;
	uint8_t senderMAC[6];
	uint32_t senderIP;
	uint8_t targetMAC[6];
	uint32_t targetIP;
};