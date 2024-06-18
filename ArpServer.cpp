#include "ArpServer.h"

ArpServer::~ArpServer()
{
    Kill();
}

void ArpServer::Initialize(const std::string& ip4Addr)
{
	dhandler.SelectInterfaceByIP4(ip4Addr, "arp");
}

void ArpServer::Start()
{
    arpThread = std::thread(&ArpServer::ProccessARP, this);
}

void ArpServer::Kill()
{
    isRunning = false;
    if (arpThread.joinable())
    {
        arpThread.join();
    }
}

MAC ArpServer::GetMacForIP4(uint32_t ip) const
{
	return table.GetMAC(ip);
}

void ArpServer::ProccessMissing()
{
    MissingArpRecord record = table.PopMissingArp();
    while (record.targetIP != 0x00000000)
    {
        SendRequest(record.senderIP, record.targetIP);

        record = table.PopMissingArp();
    }
}

void ArpServer::ProccessARP()
{
    pcap_pkthdr* header;
    const uint8_t* pkt_data;
    ArpFrame* frame;

    isRunning = true;

    while (isRunning)
    {
        ProccessMissing();

        if (dhandler.GetPacket(&header, &pkt_data) == 0)
        {
            /* Timeout elapsed */
            continue;
        }

        frame = (ArpFrame*)(pkt_data);

        // обрабатывать arp-пакеты только от шлюзов
        if (netConfig.find(frame->senderIP) == netConfig.end())
        {
            continue;
        }

        switch ((ArpTypes)(frame->opcode))
        {
        case ArpTypes::REQUEST:
            ProccessRequest(frame);
            break;
        case ArpTypes::REPLY:
            ProccessReply(frame);
            break;
        default:
            break;
        }
    }
}

void ArpServer::ProccessRequest(const ArpFrame* frame)
{   
    std::map<uint32_t, HostNetConfig>::const_iterator iter = netConfig.find(frame->senderIP);
    
    if (iter == netConfig.end())
    {
        return;
    }
    const HostNetConfig* hostData = &(iter->second);

    table.PutMACFor(frame->senderIP, frame->senderMAC);
    ArpFrame reply;
        
    reply.eth.dst = frame->senderMAC;    
    reply.eth.src = hostData->mac;
    reply.eth.proto = (uint16_t)EthTypes::ARP;

    reply.hardware = 0x0100;
    reply.protocol = 0x0008;
    reply.hardwareSize = 0x06;
    reply.protocolSize = 0x04;
    reply.opcode = (uint16_t)ArpTypes::REPLY;
    
    reply.senderMAC = hostData->mac;
    reply.senderIP = hostData->ip;
        
    reply.targetMAC = frame->senderMAC;
    reply.targetIP = frame->senderIP;

    dhandler.SendPacket(&reply, sizeof(ArpFrame));
}

void ArpServer::ProccessReply(const ArpFrame* frame)
{
    table.PutMACFor(frame->senderIP, frame->senderMAC);
}

void ArpServer::SendRequest(uint32_t senderIP, uint32_t targetIP)
{
    std::map<uint32_t, HostNetConfig>::const_iterator iter = netConfig.find(targetIP);

    if (iter == netConfig.end() || senderIP != iter->second.ip)
    {
        return;
    }
    
    const HostNetConfig* hostData = &(iter->second);    
   
    ArpFrame request;
    
    memset(request.eth.dst.bytes, 0xff, sizeof(MAC));
    request.eth.src = hostData->mac;
    request.eth.proto = (uint16_t)EthTypes::ARP;

    request.hardware = 0x0100;
    request.protocol = 0x0008;
    request.hardwareSize = 0x06;
    request.protocolSize = 0x04;
    request.opcode = (uint16_t)ArpTypes::REQUEST;


    request.senderMAC = hostData->mac;
    request.senderIP = hostData->ip;

    memset(request.targetMAC.bytes, 0x00, sizeof(MAC));
    request.targetIP = targetIP;

    dhandler.SendPacket(&request, sizeof(ArpFrame));
}


