#include <cstdint>
#include <cstring>
#include "InetProto.h"

// Internet cheksumm used in ICMP
uint16_t INET_cksum(const uint8_t* buf, int len)
{
	uint32_t sum = 0;
	uint16_t templ = 0;

	while (len > 1) {
		len -= 2;
		memcpy(&templ, buf + len, 2);
		sum += templ;
		if (sum & 0x80000000)
			sum = (sum & 0xffff) + (sum >> 16);
	}

	if (len) {
		memcpy(&templ, buf + len, len);
		sum += templ;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	
	if (sum == 0xffff) return sum;
	
	return ~sum;
}

bool ICMP_Valid(const uint8_t* icmp, const int ICMP_LEN)
{
	uint8_t* templ = new uint8_t[ICMP_LEN];
	uint16_t tImit = 0;
	memcpy(&tImit, icmp + 2, 2);
	memcpy(templ, icmp, ICMP_LEN);

	if (ICMP_LEN < 4)
		return false;

	templ[2] = 0x00;
	templ[3] = 0x00;

	if (INET_cksum(templ, ICMP_LEN) != tImit) {
		delete[] templ;
		return false;
	}

	delete[] templ;
	return true;
}