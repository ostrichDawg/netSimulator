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

        if (IsARP(pkt_data, header->len))
        {
            ProccesARP(pkt_data, header->len);
        }
        else if (IsICMP(pkt_data, header->len))
        {
            ProccessICMP(pkt_data, header->len);
        }
    }
}

inline bool NSimulator::IsARP(const u_char* pkt_data)
{
    uint16_t* type = (uint16_t*)(pkt_data + PACKET_TYPE_POS);

    return (ArpTypes)*type == ArpTypes::ARP;
}

inline bool NSimulator::IsICMP(const u_char* pkt_data, int pktSize)
{
    return false;
}

void NSimulator::ProccessICMP(const u_char* pkt_data, int pktSize)
{
}

void NSimulator::ProccessArpRequest(const u_char* pkt_data)
{
    uint32_t* senderIP = (uint32_t*)(pkt_data + (int)ArpPositions::SENDER_IP);
    MAC* senderMAC = (MAC*)(pkt_data + (int)ArpPositions::SENDER_MAC);

    arpTable[*senderIP] = *senderMAC;

    uint8_t reply[42];
    memcpy(reply, senderMAC, sizeof(MAC));
    memcpy(reply + sizeof(MAC), netFor[*senderIP].mac.bytes, sizeof(MAC));

    reply[12] = 0x08;
    reply[13] = 0x06;

    reply[14] = 0x00;
    reply[15] = 0x01;

    reply[16] = 0x08;
    reply[17] = 0x00;

    reply[18] = 0x06;

    reply[19] = 0x04;

    reply[20] = 0x00;
    reply[21] = 0x02;

    memcpy(reply + (int)ArpPositions::SENDER_MAC, netFor[*senderIP].mac.bytes, sizeof(MAC));
    memcpy(reply + (int)ArpPositions::SENDER_IP, &netFor[*senderIP].ip, sizeof(uint32_t));

    memcpy(reply + (int)ArpPositions::TARGET_MAC, senderMAC->bytes, sizeof(MAC));
    memcpy(reply + (int)ArpPositions::TARGET_IP, senderIP, sizeof(uint32_t));

    pcap_sendpacket(adhandle, reply, 42);
}

void NSimulator::ProccessArpReply(const u_char* pkt_data)
{
    uint32_t* senderIP = (uint32_t*)(pkt_data + (int)ArpPositions::SENDER_IP);
    MAC* senderMAC = (MAC*)(pkt_data + (int)ArpPositions::SENDER_MAC);

    arpTable[*senderIP] = *senderMAC;
}

void NSimulator::ProccesARP(const u_char* pkt_data)
{
    uint16_t* operation = (uint16_t*)(pkt_data + (int)ArpPositions::OPERATION);

    switch ((ArpTypes)(*operation))
    {
    case ArpTypes::REQUEST:
        ProccessArpRequest(pkt_data);
        break;

    case ArpTypes::REPLY:
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
        std::cout <<  ++i << ". " << device->name;
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
    std::cout << "Enter the interface number (1 -" << numberOfDevices << "): ";
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
        // 65536 guarantees that the whole packet will be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
        1000,             // read timeout
        NULL,             // authentication on the remote machine
        errbuf            // error buffer
    )) == NULL)
    {
        throw std::runtime_error(errbuf);
    }
}


