#include "NetInterface.h"

void NetInterface::SelectInterface(const std::string& filterString)
{
    pcap_if_t* alldevs = nullptr;

    try
    {
        FindAllDevices(&alldevs);
        PrintDevicesList(alldevs);
        SetDevice(alldevs, filterString);

        pcap_freealldevs(alldevs);
    }
    catch (std::exception& e)
    {
        if (alldevs != nullptr)
        {
            pcap_freealldevs(alldevs);
        }

        throw;
    }
}

void NetInterface::SelectInterfaceByIP4(const std::string& ip4Addr, const std::string& filterString)
{
    pcap_if_t* alldevs;

    try
    {
        FindAllDevices(&alldevs);
        SetDeviceByIP4(ip4Addr, alldevs, filterString);

        pcap_freealldevs(alldevs);
    }
    catch (std::exception& e)
    {
        if (alldevs != nullptr)
        {
            pcap_freealldevs(alldevs);
        }

        throw;
    }
}

void NetInterface::SendPacket(const void* pkt_data, size_t pkt_size)
{
    if (pcap_sendpacket(adhandle, (const u_char*)pkt_data, pkt_size) != 0)
    {
        throw std::runtime_error("Error sending packet!");
    }
}

int NetInterface::GetPacket(pcap_pkthdr** header, const u_char** pkt_data)
{
    int res = pcap_next_ex(adhandle, header, pkt_data);
    if (res < 0)
    {
        throw std::runtime_error("Error receiving packet!");
    }

    return res;
}

void NetInterface::FindAllDevices(pcap_if_t** alldevs)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &(*alldevs), errbuf) == -1)
    {
        throw std::runtime_error(errbuf);
    }

    pcap_if_t* device;
    for (device = *alldevs; device != nullptr; device = device->next)
    {
        numberOfDevices++;
    }
}

void NetInterface::PrintDevicesList(pcap_if_t* alldevs)
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
}

void NetInterface::SetDevice(pcap_if_t* alldevs, const std::string& filterString)
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
    for (device = alldevs, i = 0; i < deviceNumber - 1; device = device->next, i++);

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

    if (filterString.size() != 0)
    {
        SetFilter(device, filterString);
    }
}

void NetInterface::SetDeviceByIP4(const std::string& ip4Addr, pcap_if_t* alldevs, const std::string& filterString)
{
    pcap_if_t* device;
    int i;
    for (device = alldevs, i = 0; i < numberOfDevices; device = device->next, i++)
    {
        if (((sockaddr_in*)device->addresses->addr)->sin_addr.S_un.S_addr == inet_addr(ip4Addr.data()))
            break;
    }

    if (i == numberOfDevices)
    {
        throw std::runtime_error("Device with address " + ip4Addr + " was not found!");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    /* Open the device */
    if ((adhandle = pcap_open_live(device->name,          // name of the device
        65536,            // portion of the packet to capture. 
        PCAP_OPENFLAG_NOCAPTURE_LOCAL,
        50,               // read timeout
        errbuf            // error buffer
    )) == NULL)
    {
        throw std::runtime_error(errbuf);
    }

    if (filterString.size() != 0)
    {
        SetFilter(device, filterString);
    }
}

void NetInterface::SetFilter(pcap_if_t* device, const std::string& filterString)
{
    uint32_t netmask;
    if (device->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask = 0xffffffff;    

    bpf_program fcode;

    //compile the filter
    if (pcap_compile(adhandle, &fcode, filterString.data(), 1, netmask) < 0)
    {
        throw std::runtime_error("Unable to compile the packet filter. Check the syntax.");        
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        throw std::runtime_error("Error setting the filter.");
    }
}
