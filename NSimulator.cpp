#include "NSimulator.h"

void NSimulator::SetDeviceHandler()
{
    pcap_if_t* alldevs;

    try
    {
        FindAllDevices(&alldevs);
        PrintDevicesList(alldevs);
        SelectDevice(alldevs);
        
        pcap_freealldevs(alldevs);
    }
    catch (std::exception& e)
    {
        if (alldevs != nullptr)
        {
            pcap_freealldevs(alldevs);
        }

        std::cerr << e.what() << std::endl;
    }
}

void NSimulator::GetPacketsLoop()
{
    if (adhandle == nullptr)
    {
        throw std::runtime_error("Pointer to device handler can't be null!");
    }

    int res;
    pcap_pkthdr* header;
    const u_char* pkt_data;
    /* Retrieve the packets */
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0)
        {
            /* Timeout elapsed */
            continue;
        }
        
        if (IsARP(pkt_data))
        {
            ProccesARP(pkt_data);
        }
        else if (IsICMP(pkt_data))
        {
            ProccessICMP(pkt_data, header->len);
        }
    }
}

inline bool NSimulator::IsARP(const void* pkt_data)
{
    EthHeader* ethHeader = (EthHeader*)(pkt_data);
    return ethHeader->proto == (uint16_t)EthTypes::ARP;
}

inline bool NSimulator::IsICMP(const void* pkt_data)
{
    Ip4Frame* frame = (Ip4Frame*)(pkt_data);
    return frame->ip4.protocol == (uint16_t)IP4Types::ICMP;
}

void NSimulator::ProccessICMP(const void* pkt_data, int pktSize)
{
    IcmpFrame* frame = (IcmpFrame*) pkt_data;

    switch ((IcmpTypes)frame->type)
    {
    case IcmpTypes::REQUEST:
        ProccessICMPRequest(pkt_data, pktSize);
        break;
    case IcmpTypes::REPLY:
        ProccessICMPReply(pkt_data, pktSize);
        break;
    default:
        break;
    }
}

void NSimulator::ProccessICMPRequest(const void* pkt_data, int pktSize)
{
    IcmpFrame* request = (IcmpFrame*)pkt_data;

    std::vector<uint8_t> replyRAW(pktSize);
    IcmpFrame* reply = (IcmpFrame*) replyRAW.data();

    // Prepare reply ETH header
    memcpy(reply->dst, request->src, sizeof(MAC));
    memcpy(reply->src, request->dst, sizeof(MAC));
    reply->proto = (uint16_t)EthTypes::IP4;

    // Prepare reply IP4 header
    reply->version = 0x4;
    reply->ip4HeaderLen = 0x5;
    reply->difSer = 0x00;
    reply->totalLen = request->totalLen;
    reply->identification = request->identification + 1;
    reply->flags = 0x0000;
    reply->ttl = 128;
    reply->protocol = (uint8_t)IP4Types::ICMP;
    /////////////////////////////////////////////////////////
    memcpy(reply->srcIP, request->dstIP, 4);    // need to get
    memcpy(reply->dstIP, request->srcIP, 4);    // need to get
    
    reply->headerCSum = 0x0000;          // NEED TO COUNT
    /////////////////////////////////////////////////////////

    // Prepare reply ICMP header
    reply->type = (uint8_t)IcmpTypes::REPLY;
    reply->code = 0x00;
    reply->identifier = request->identifier;  
    reply->seqNum = request->seqNum;  
    reply->checkSum = 0x0000;  // NEED TO COUNT

    memcpy(replyRAW.data() + sizeof(IcmpFrame), ((uint8_t*) pkt_data) + sizeof(IcmpFrame), pktSize - sizeof(IcmpFrame));
    pcap_sendpacket(adhandle, replyRAW.data(), pktSize);
}

inline void NSimulator::ProccessICMPReply(const void* pkt_data, int pktSize)
{
}

void NSimulator::ProccessArpRequest(const void* pkt_data)
{
    //ArpFrame* request = (ArpFrame*)pkt_data;
    //
    //arpTable[request->senderIP] = *( (MAC*)request->senderMAC );

    //ArpFrame reply;    

    //NetCFG hostData = netFor[request->senderIP];

    //memcpy(reply.dst, request->senderMAC, sizeof(MAC));
    //memcpy(reply.src, hostData.mac.bytes, sizeof(MAC));
    //
    //reply.proto = (uint16_t)EthTypes::ARP;
    //reply.hardware = 0x0100;
    //reply.protocol = 0x0008;
    //reply.hardwareSize = 0x06;
    //reply.protocolSize = 0x04;
    //reply.opcode = (uint16_t)ArpTypes::REPLY; 

    //memcpy(reply.senderMAC, hostData.mac.bytes, sizeof(MAC));
    //reply.senderIP = hostData.ip;

    //memcpy(reply.targetMAC, request->senderMAC, sizeof(MAC));
    //reply.targetIP = request->senderIP;

    //pcap_sendpacket(adhandle, (const uint8_t*) &reply, sizeof(ArpFrame));
}

void NSimulator::ProccessArpReply(const void* pkt_data)
{
    ArpFrame* reply = (ArpFrame*)(pkt_data);
    arpTable[reply->senderIP] = *( (MAC*)reply->senderMAC );
}

void NSimulator::ProccesARP(const void* pkt_data)
{
    ArpFrame* frame = (ArpFrame*)(pkt_data);

    switch ((ArpTypes)(frame->opcode))
    {
    case ArpTypes::REQUEST :
        ProccessArpRequest(pkt_data);
        break;
    case ArpTypes::REPLY :
        ProccessArpReply(pkt_data);
        break;

    default:
        break;
    }
}

void NSimulator::FindAllDevices(pcap_if_t** alldevs)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &(*alldevs), errbuf) == -1)
    {
        throw std::runtime_error(errbuf);
    }
}

void NSimulator::PrintDevicesList(pcap_if_t* alldevs)
{
    if (alldevs == nullptr)
    {
        throw std::runtime_error("Pointer to devices list can't be null!");
    }

    pcap_if_t* device;
    int i = 0;
    for (device = alldevs; device != nullptr; device = device->next)
    {
        std::cout << ++i << ". " << device->name;
        if (device->description)
            std::cout << " (" << device->description << ")\n";
        else
            std::cout << " (No description available)\n";
    }
    
    numberOfDevices = i;
}

void NSimulator::SelectDevice(pcap_if_t* alldevs)
{
    int deviceNumber = 0;
    std::cout << "Enter the interface number (1 - " << numberOfDevices << "): ";
    std::cin >> deviceNumber;   
    
    if (deviceNumber < 1 || deviceNumber > numberOfDevices)
    {
        throw std::runtime_error("Invalid device number!");
    }

    pcap_if_t* device;
    int i;
    for (device = alldevs, i = 0; i < numberOfDevices - 1; device = device->next, i++);

    char errbuf[PCAP_ERRBUF_SIZE];
    /* Open the device */
    if ((adhandle = pcap_open(device->name,          // name of the device
        65536,            // portion of the packet to capture. 
        PCAP_OPENFLAG_NOCAPTURE_LOCAL,    
        1000,             // read timeout
        NULL,             // authentication on the remote machine
        errbuf            // error buffer
    )) == NULL)
    {
        throw std::runtime_error(errbuf);
    }
}
