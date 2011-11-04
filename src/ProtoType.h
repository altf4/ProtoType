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
#include <time.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <tr1/unordered_map>

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

//Number of dimensions
#define DIM	9

//First == protocol, second == votes
typedef std::tr1::unordered_map<int, int> protocolCountTable;
protocolCountTable protocolCount;

//The feature set
double featureSet[DIM];

//Used to calculate normalization
double maxFeatureValues[DIM];

//For every packet, we need to keep track of 3 things:
//	-The ethernet header (IE the only thing in plaintext)
//	-Timestamp when it was received
//	-How big the whole packet was
struct packet_t
{
	struct ether_addr eth_src_addr;
	struct ether_addr eth_dest_addr;
	time_t timestamp;
	uint len;
};

//Keep track of which end is the "Tx" and which is the "Rx"
struct ether_addr etherTxAddress;
struct ether_addr etherRxAddress;

//An array of the last batch of packets
//	(Gets cleared out after classification)
vector <packet_t> packetlist;

//###################################################################
//The dependency variables
//IE: Values used to calculate the above feature set

//Used to calculate PACKET_SIZE_MEAN
uint RxTotalBytes, TxTotalBytes;
uint RxTotalPackets, TxTotalPackets;

//Used to calculate PACKET_SIZE_VARIANCE
vector <uint> TxPacketSizes, RxPacketSizes;

//Used to calculate PACKET_INTERARRIVAL_VARIANCE
vector <time_t> TxInterarrivalTimes, RxInterarrivalTimes;
time_t RxLastPacketArrivalTime=0, TxLastPacketArrivalTime=0;
//###################################################################

//Classification variables
const uint k = 3;
const double eps = 0;
int maxPts = 1000;
int nPts = 0;


//Function declarations
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void *ClassificationLoop(void* ptr);
void *TrainingLoop(void* ptr);

void LoadDataPointsFromFile(string filePath);
void WriteDataPointsToFile(int sig);

void CalculateDependencyVariables(packet_t packet);
void CalculateFeatureSet();
void NormalizeDataPoints();
void Classify();


bool CompareEthAddresses(struct ether_addr *addr1, struct ether_addr *addr2);

string Usage();

#endif /* PROTOTYPE_H_ */
