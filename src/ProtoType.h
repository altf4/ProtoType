//============================================================================
// Name        : ProtoType.h
// Author      : AltF4
// Copyright   : GNU GPL v3
// Description : ProtoType, a traffic analysis attack to classify
//					protocols through encryption
//============================================================================

#ifndef PROTOTYPE_H_
#define PROTOTYPE_H_

#include <vector>
#include <signal.h>

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
#define TX_RX_BYTE_RATIO				8

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

//Function declarations
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void *ClassificationLoop(void* ptr);
void *TrainingLoop(void* ptr);

void LoadDataPointsFromFile(char* filePath);
void WriteDataPointsToFile(int sig);

void CalculateDependencyVariables();
void CalculateFeatureSet();
void Classify();

string Usage();

#endif /* PROTOTYPE_H_ */
