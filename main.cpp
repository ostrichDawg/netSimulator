#include <string>
#include <fstream>

#include "ArpServer.h"
#include "IcmpServer.h"

MAC StrToMac(const std::string& str)
{
	MAC mac;
	if (sscanf(str.data(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac.bytes[0], &mac.bytes[1], &mac.bytes[2], &mac.bytes[3], &mac.bytes[4], &mac.bytes[5]) != 6)
	{
		throw std::runtime_error(str + " is invalid mac address!");
	}

	return mac;
}

HostNetConfig GetHostConfig(std::ifstream& configReader)
{
	HostNetConfig host;

	std::string str;

	// read host ip4 address	
	configReader >> str;
	if (inet_addr(str.data()) == -1)
	{
		throw std::runtime_error(str + " is invalid ip4 address!");
	}
	host.ip = inet_addr(str.data());

	// read host's gateway ip4 address	
	configReader >> str;
	if (inet_addr(str.data()) == -1)
	{
		throw std::runtime_error(str + " is invalid ip4 address!");
	}
	host.gateway = inet_addr(str.data());

	configReader >> str;
	host.mac = StrToMac(str);

	return host;
}

int main(int argc, char* argv[])
{

	if (argc != 2)
	{
		std::cerr << "Network adapter's ip4 address is required!";
		return -1;
	}

	std::ifstream configReader("net_config.txt");
	if (configReader.is_open() == false)
	{
		return -1;
	}
	
	// key is a gateway's ip4 address
	std::map<uint32_t, HostNetConfig> tableForARP;	

	// key is a host's ip4 address
	std::map<uint32_t, HostNetConfig> tableForICMP;

	try 
	{
		while (configReader.eof() != true)
		{
			HostNetConfig host = GetHostConfig(configReader);
			tableForARP[host.gateway] = host;
			tableForICMP[host.ip] = host;
		}
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return -1;
	}

	SafeArpTable table;	

	ArpServer arpServer(table, tableForARP);
	IcmpServer icmpServer(table, tableForICMP);

	try
	{
		arpServer.Initialize(argv[1]);
		arpServer.Start();
		
		icmpServer.Initialize(argv[1]);
		icmpServer.Start();				

		getchar();
		arpServer.Kill();
		icmpServer.Kill();
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;		
		return -1;
	}

	return 0;
}