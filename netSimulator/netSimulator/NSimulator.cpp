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
    }
}

bool NSimulator::IsARP(const u_char* pkt_data, int pkt_size)
{
    uint16_t* type = (uint16_t*)(pkt_data + PACKET_TYPE_POS);

    if (*type == ARP_PACKET_TYPE)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void NSimulator::ProccesARP(const u_char* pkt_data, int pkt_size)
{
    uint16_t* operation = (uint16_t*)(pkt_data + ARP_OPERATION_POS);

    switch (*operation)
    {
    case ARP_REQUEST:
        break;

    case ARP_REPLY:
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


