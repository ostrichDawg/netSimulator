#pragma once

uint16_t INET_cksum(const uint8_t* buf, int len);
bool ICMP_Valid(const uint8_t* icmp, const int ICMP_LEN);