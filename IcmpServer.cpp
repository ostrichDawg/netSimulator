#include "IcmpServer.h"

using namespace std::chrono;

IcmpServer::~IcmpServer()
{
	Kill();
}

void IcmpServer::Initialize(const std::string& ip4Addr)
{
	senderIf.SelectInterfaceByIP4(ip4Addr, "");
	receiverIf.SelectInterfaceByIP4(ip4Addr, "icmp");
}

void IcmpServer::Start()
{
	isRunning = true;
	try
	{
		senderThread = std::thread(&IcmpServer::StartSender, this);
		receiverThread = std::thread(&IcmpServer::StartReceiver, this);
	}
	catch (...)
	{
		Kill();
		throw;
	}
}

void IcmpServer::Kill()
{
	isRunning = false;

	if (senderThread.joinable())
	{
		senderThread.join();
	}

	if (receiverThread.joinable())
	{
		receiverThread.join();
	}
}

void IcmpServer::StartSender()
{
	uint16_t seqNum = 0;
	std::vector<uint8_t> requestFrameRaw(74);

	for (int i = sizeof(IcmpFrame); i < requestFrameRaw.size(); ++i)
	{
		requestFrameRaw[i] = ('a' + (i % sizeof(IcmpFrame))) % 26;
	}

	while (isRunning)
	{
		auto start = high_resolution_clock::now();

		// senderData.first - sender host IP
		for (const std::pair<uint32_t, HostNetConfig>& senderData : netConfig)
		{
			try
			{
				// receiverData.first - receiver host IP
				for (const std::pair<uint32_t, HostNetConfig>& receiverData : netConfig)
				{
					// Не отправлять пакеты самому себе
					if (senderData.first == receiverData.first)
					{
						continue;
					}

					SendICMPRequestFromTo(senderData.second, receiverData.second.ip, requestFrameRaw,++seqNum);
				}
			}
			catch (std::exception& e)
			{
				std::cerr << e.what() << std::endl;
				continue;
			}
		}

		// проверить icmp-ответы через пол секунды
		while (duration_cast<microseconds>(high_resolution_clock::now() - start).count() < 5000)
		{}
		ProccessNoReplys();
		
		// отправлять icmp-запросы каждую секунду
		while (duration_cast<microseconds>(high_resolution_clock::now() - start).count() < 1000000)
		{}
	}
}

void IcmpServer::StartReceiver()
{
	pcap_pkthdr* header;
	const uint8_t* pkt_data;
	IcmpFrame* frame;

	while (isRunning)
	{
		if (receiverIf.GetPacket(&header, &pkt_data) == 0)
		{
			continue;    // Timeout elapsed
		}

		frame = (IcmpFrame*)(pkt_data);	

		// Не обрабатывать мной сгенерированные пакеты
		std::map<uint32_t, HostNetConfig>::const_iterator iter = netConfig.find(frame->ip4.src);		
		if (memcmp(frame->eth.src.bytes, iter->second.mac.bytes, sizeof(MAC)) == 0)
		{
			continue;
		}

		switch ((IcmpTypes)frame->icmp.type)
		{
		case IcmpTypes::REQUEST:
			ProccessICMPRequest(frame, header->caplen);
			break;
		case IcmpTypes::REPLY:
			ProccessICMPReply(frame, header->caplen);
			break;
		default:
			break;
		}
	}
}

// senderData - IP, MAC и шлюз отправителя
// receiverIP - IP адресс получателя
void IcmpServer::SendICMPRequestFromTo(const HostNetConfig& senderData, uint32_t receiverIP, std::vector<uint8_t>& requestRAW, uint16_t seqNum)
{
	IcmpFrame* request = (IcmpFrame*)requestRAW.data();

	// Prepare reply ETH header

	try
	{
		request->eth.dst = arpTable.GetMAC(senderData.gateway);
	}
	catch (const std::exception& e)
	{
		arpTable.PutMissing(senderData.gateway, senderData.ip);
		throw;
	}

	request->eth.src = senderData.mac;
	request->eth.proto = (uint16_t)EthTypes::IP4;

	// Prepare request IP4 header
	uint16_t totalLen = requestRAW.size() - sizeof(EthHeader);

	request->ip4.v_l = 0x45;
	request->ip4.difSer = 0x00;
	request->ip4.totalLen = (totalLen << 8) ^ (totalLen >> 8);
	request->ip4.id = 0x0100;
	request->ip4.flags = 0x0000;
	request->ip4.ttl = 128;
	request->ip4.protocol = (uint8_t)IP4Types::ICMP;
	request->ip4.src = senderData.ip;
	request->ip4.dst = receiverIP;
	request->ip4.headerCSum = 0x0000;        // NEED TO COUNT

	// Prepare request ICMP header
	request->icmp.type = (uint8_t)IcmpTypes::REQUEST;
	request->icmp.code = 0x00;
	request->icmp.id = 1;
	request->icmp.checkSum = 0x0000;
	request->icmp.seqNum = seqNum;

	request->icmp.checkSum = INET_cksum(requestRAW.data() + sizeof(Ip4Frame), requestRAW.size() - sizeof(Ip4Frame));

	std::lock_guard<std::mutex> lock(noReplyMutex);
	noReplyStore[seqNum] = std::make_pair(senderData.ip, receiverIP);

	senderIf.SendPacket(requestRAW.data(), requestRAW.size());
}

void IcmpServer::ProccessICMPRequest(const IcmpFrame* frame, int pktSize)
{
	if (ICMP_Valid((uint8_t*)frame + sizeof(Ip4Frame), pktSize - sizeof(Ip4Frame)) != true)
	{
		return;
	}

	static std::vector<uint8_t> replyRAW;
	if (replyRAW.size() != pktSize)
	{
		replyRAW.resize(pktSize);
		memcpy(replyRAW.data() + sizeof(IcmpFrame), ((uint8_t*)frame) + sizeof(IcmpFrame), pktSize - sizeof(IcmpFrame));
	}

	IcmpFrame* reply = (IcmpFrame*)replyRAW.data();

	// Prepare reply ETH header
	reply->eth.dst = frame->eth.src;
	reply->eth.src = frame->eth.dst;
	reply->eth.proto = (uint16_t)EthTypes::IP4;

	// Prepare reply IP4 header
	reply->ip4.v_l = 0x45;
	reply->ip4.difSer = 0x00;
	reply->ip4.totalLen = frame->ip4.totalLen;
	reply->ip4.id = frame->ip4.id + 1;
	reply->ip4.flags = 0x0000;
	reply->ip4.ttl = 128;
	reply->ip4.protocol = (uint8_t)IP4Types::ICMP;
	/////////////////////////////////////////////////////////
	reply->ip4.src = frame->ip4.dst;    // need to get
	reply->ip4.dst = frame->ip4.src;    // need to get

	reply->ip4.headerCSum = 0x0000;     // NEED TO COUNT
	/////////////////////////////////////////////////////////

	// Prepare reply ICMP header
	reply->icmp.type = (uint8_t)IcmpTypes::REPLY;
	reply->icmp.code = 0x00;
	reply->icmp.id = frame->icmp.id;
	reply->icmp.seqNum = frame->icmp.seqNum;
	reply->icmp.checkSum = 0x0000;

	reply->icmp.checkSum = INET_cksum(replyRAW.data() + sizeof(Ip4Frame), replyRAW.size() - sizeof(Ip4Frame));

	receiverIf.SendPacket(replyRAW.data(), replyRAW.size());
}

void IcmpServer::ProccessICMPReply(const IcmpFrame* frame, int pktSize)
{
	if (ICMP_Valid((uint8_t*)frame + sizeof(Ip4Frame), pktSize - sizeof(Ip4Frame)) != true)
	{
		return;
	}

	std::lock_guard<std::mutex> lock(noReplyMutex);
	noReplyStore.erase(frame->icmp.seqNum);
}

void IcmpServer::ProccessNoReplys()
{
	in_addr addr;

	std::lock_guard<std::mutex> lock(noReplyMutex);
	for (const std::pair<uint16_t, std::pair<uint32_t, uint32_t>>& record : noReplyStore)
	{
		addr.s_addr = record.second.first;
		std::cout << "No reply for " << inet_ntoa(addr);
		
		addr.s_addr = record.second.second;
		std::cout << " from: " << inet_ntoa(addr);
		std::cout << " (seqnum: " << record.first << " )" << std::endl;
	}

	noReplyStore.clear();
}
