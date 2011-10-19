//============================================================================
// Name        : ProtoType.cpp
// Author      : AltF4
// Copyright   : GNU GPL v3
// Description : Hello World in C++, Ansi-style
//============================================================================

#ifndef PROTOTYPE_H_
#define PROTOTYPE_H_

#include <vector>

using namespace std;

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

//The feature set:
#define TX_PACKET_SIZE_MEAN				0
#define RX_PACKET_SIZE_MEAN				1
#define TX_PACKET_SIZE_VARIANCE			2
#define RX_PACKET_SIZE_VARIANCE			3
#define TX_PACKET_INTERARRIVAL_MEAN		4
#define RX_PACKET_INTERARRIVAL_MEAN		5
#define TX_PACKET_INTERARRIVAL_VARIANCE	6
#define RX_PACKET_INTERARRIVAL_VARIANCE	7

//The dependency variables
//IE: Values used to calculate the above feature set

//Used to calculate PACKET_SIZE_MEAN
uint RxTotalBytes, TxTotalBytes;
uint RxTotalPackets, TxTotalPackets;

//Used to calculate PACKET_SIZE_VARIANCE
vector <uint> TxPacketSizes, RxPacketSizes;

//Used to calculate PACKET_INTERARRIVAL_MEAN
uint RxTotalInterarrivalTime, TxTotalInterarrivalTime;
//Also uses RxTotalPackets, TxTotalPackets from above

//Used to calculate PACKET_INTERARRIVAL_VARIANCE
vector <uint> TxInterarrivalTimes, RxInterarrivalTimes;

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void *ClassificationLoop(void* ptr);

string Usage();

#endif /* PROTOTYPE_H_ */
