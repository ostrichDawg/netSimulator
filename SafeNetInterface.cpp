#include "SafeNetInterface.h"

void SafeNetInterface::SelectInterfaceByIP4(const std::string& ip4Addr, const std::string& filterString)
{
    std::lock_guard<std::mutex> lock(mutex);

    if (adhandle != nullptr)
    {
        throw std::runtime_error("Network device is already setted!");
    }

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

        std::cerr << e.what() << std::endl;
    }
}

void SafeNetInterface::SendPacket(const void* pkt_data, size_t pkt_size)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pcap_sendpacket(adhandle, (const u_char*)pkt_data, pkt_size) != 0)
    {
        throw std::runtime_error("Error sending packet!");
    }
}

int SafeNetInterface::GetPacket(pcap_pkthdr** header, const u_char** pkt_data)
{
    std::lock_guard<std::mutex> lock(mutex);
    int res = pcap_next_ex(adhandle, header, pkt_data);
    if (res < 0)
    {
        throw std::runtime_error("Error receiving packet!");
    }

    return res;
}

void SafeNetInterface::FindAllDevices(pcap_if_t** alldevs)
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

void SafeNetInterface::SetDeviceByIP4(const std::string& ip4Addr, pcap_if_t* alldevs, const std::string& filterString)
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

void SafeNetInterface::SetFilter(pcap_if_t* device, const std::string& filterString)
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
