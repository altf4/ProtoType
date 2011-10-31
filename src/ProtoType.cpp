//============================================================================
// Name        : ProtoType.cpp
// Author      : AltF4
// Copyright   : GNU GPL v3
// Description : ProtoType, a traffic analysis attack to classify
//					protocols through encryption
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <iostream>
#include "ProtoType.h"
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <math.h>
#include <ANN/ANN.h>


using namespace std;

uint classificationTimeout = 200;
bool isTraining = true;
string dataFilePath;

int main (int argc, char **argv)
{
	int c;
	char errbuf[PCAP_ERRBUF_SIZE];
	string dev;
	pcap_t *handle;
	pthread_t classificationThread, trainingThread;

	signal(SIGINT,WriteDataPointsToFile);

	while ((c = getopt (argc, argv, ":i:t:c:m:d:s:")) != -1)
	{
		switch (c)
		{
			case 'i':
			{
				dev.assign(optarg);
				break;
			}
			case 'm':
			{
				int tempArg = atoi(optarg);
				if(tempArg > 0)
				{
					classificationTimeout = tempArg;
				}
				else
				{
					cerr << "The value you entered for Classification "
							"Timeout must be an integer greater than Zero.\n";
					cout << Usage();
				}
				break;
			}
			case 't':
			{
				isTraining = true;
				if(optarg == NULL)
				{
					cout << "Path to data file is Null.\n";
					cout << Usage();
					exit(-1);
				}
				dataFilePath.assign(optarg);
				break;
			}
			case 'c':
			{
				isTraining = false;
				dataFilePath.assign(optarg);
				LoadDataPointsFromFile(dataFilePath);
				break;
			}
			case 's':
			{
				//TODO: Accept and validate hw address input
				//	to etherRxAddress
				break;
			}
			case 'd':
			{
				//TODO: Accept and validate hw address input
				//	to etherTxAddress
				break;
			}
			case '?':
			{
				if (isprint (optopt))
				{
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				}
				else
				{
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				}
				cout << Usage();
				return 1;

			}
			default:
			{
				cout << Usage();
				return 1;
			}
		}
	}

	//Initialize the ethernet addresses to empty
	bzero(etherTxAddress, sizeof(etherTxAddress));
	bzero(etherRxAddress, sizeof(etherRxAddress));

	if(isTraining)
	{
		//Start the Classification Loop
		pthread_create( &trainingThread, NULL, TrainingLoop, NULL);
	}
	else
	{
		//Start the Classification Loop
		pthread_create( &classificationThread, NULL, ClassificationLoop, NULL);
	}



	//Start listening for packets
	handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
	pcap_loop(handle, 0, PacketHandler, NULL);

	return 0;
}

//Gets called each time a packet arrives.
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	packet_t thisPacket;

	thisPacket.timestamp = header->ts.tv_sec;
	thisPacket.len = header->len;
	memcpy( thisPacket.eth_hdr, packet, ETH_ALEN);

	packetlist.push_back(thisPacket);
}

//Periodically wakes up and reclassifies the data.
//	We wouldn't want to do this for every new packet, that'd be crazy
void *ClassificationLoop(void *ptr)
{
	//Keep looping
	while(true)
	{
		sleep(classificationTimeout);

		//For the new packet's we've accumulated, recalculate
		//	Dependency variables
		for(uint i = 0; i < packetlist.size(); i++)
		{
			CalculateDependencyVariables(packetlist[i]);
		}
		packetlist.clear();

		//TODO: Perform the classification
		CalculateFeatureSet();
		Classify();

	}

	//Shouldn't get here. This is just to get rid of the compiler warning.
	return NULL;
}

//On training mode, reclassify data points periodically
void *TrainingLoop(void *ptr)
{
	//Keep looping
	while(true)
	{
		sleep(classificationTimeout);

		//TODO: Perform the classification
	}

	//Shouldn't get here. This is just to get rid of the compiler warning.
	return NULL;
}

//Called in classification mode to retrieve a stored data set
void LoadDataPointsFromFile(string filePath)
{
	if(filePath.empty())
	{
		cerr << "You entered an empty file path\n";
		cout << Usage();
		exit(1);
	}
	string line;

	//Creates an instance of ofstream, and opens example.txt
	ifstream dataFile(filePath.c_str());
	getline(dataFile,line);




	// Close the file stream explicitly
	dataFile.close();


}

//Called on training mode to save data to file
void WriteDataPointsToFile(int sig)
{
	if(dataFilePath.empty())
	{
		cerr << "You entered an empty file path. :(\n";
		cout << Usage();
		exit(1);
	}
	string line;

	//Creates an instance of ofstream, and opens example.txt
	ofstream dataStream;
	dataStream.open(dataFilePath.c_str(), fstream::out | fstream::app);

	//TODO: Do the actual writing here
	dataStream << "worked\n";

	dataStream.close();

	cout << "Data written to file. Thank you, please come again!\n";
	exit(1);
}
//Calculate the set of dependency variables for this new packet
void CalculateDependencyVariables(packet_t packet)
{
	bool isRx;

	//Pointers into the packet object for different TCP/IP layers
	struct ether_header *ethernet;

	ethernet = (struct ether_header *) packet.eth_hdr;

	if( CompareEthAddresses( ethernet->ether_shost, etherTxAddress) )
	{
		isRx = false;
	}
	else if( CompareEthAddresses( ethernet->ether_shost, etherRxAddress) )
	{
		isRx = true;
	}


	//Calculate Dependency Variables
	if(isRx)
	{
		RxTotalBytes += packet.len;
		RxTotalPackets++;

		//If this is not our first packet...
		if(RxLastPacketArrivalTime != 0)
		{
			RxInterarrivalTimes.push_back( packet.timestamp - RxLastPacketArrivalTime );
		}
		//Our first packet
		else
		{
			RxLastPacketArrivalTime = packet.timestamp;
		}
		RxPacketSizes.push_back(packet.len);
		RxLastPacketArrivalTime = packet.timestamp;
	}
	else
	{
		TxTotalBytes += packet.len;
		TxTotalPackets++;

		//If this is not our first packet...
		if(TxLastPacketArrivalTime != 0)
		{
			TxInterarrivalTimes.push_back( packet.timestamp - TxLastPacketArrivalTime );
		}
		//Our first packet
		else
		{
			TxLastPacketArrivalTime = packet.timestamp;
		}
		TxPacketSizes.push_back(packet.len);
		TxLastPacketArrivalTime = packet.timestamp;
	}

}

//Update the feature set for new evidence that's come in
void CalculateFeatureSet()
{
	//packet size mean
	featureSet[TX_PACKET_SIZE_MEAN] = TxTotalBytes / TxTotalPackets;
	featureSet[RX_PACKET_SIZE_MEAN] = RxTotalBytes / RxTotalPackets;

	//Tx Packet size variance
	double tempSum = 0;
	for(uint i = 0; i < TxPacketSizes.size(); i++)
	{
		tempSum += pow( (TxPacketSizes[i] - featureSet[TX_PACKET_SIZE_MEAN]), 2);
	}
	featureSet[TX_PACKET_SIZE_VARIANCE] = tempSum / TxPacketSizes.size();

	//Rx Packet size variance
	tempSum = 0;
	for(uint i = 0; i < RxPacketSizes.size(); i++)
	{
		tempSum += pow( (RxPacketSizes[i] - featureSet[RX_PACKET_SIZE_MEAN]), 2);
	}
	featureSet[RX_PACKET_SIZE_VARIANCE] = tempSum / RxPacketSizes.size();

	//TX_PACKET_INTERARRIVAL_MEAN
	featureSet[TX_PACKET_INTERARRIVAL_MEAN] =
		( TxInterarrivalTimes.back() - TxInterarrivalTimes.front() ) / TxTotalPackets;

	//RX_PACKET_INTERARRIVAL_MEAN
	featureSet[RX_PACKET_INTERARRIVAL_MEAN] =
		( RxInterarrivalTimes.back() - RxInterarrivalTimes.front() ) / RxTotalPackets;

	//TX_PACKET_INTERARRIVAL_VARIANCE
	tempSum = 0;
	for(uint i = 0; i < TxInterarrivalTimes.size(); i++)
	{
		tempSum += pow( (TxInterarrivalTimes[i] -
			featureSet[TX_PACKET_INTERARRIVAL_VARIANCE]), 2);
	}
	featureSet[TX_PACKET_INTERARRIVAL_VARIANCE] = tempSum / TxInterarrivalTimes.size();

	//RX_PACKET_INTERARRIVAL_VARIANCE
	tempSum = 0;
	for(uint i = 0; i < RxInterarrivalTimes.size(); i++)
	{
		tempSum += pow( (RxInterarrivalTimes[i] -
			featureSet[RX_PACKET_INTERARRIVAL_VARIANCE]), 2);
	}
	featureSet[RX_PACKET_INTERARRIVAL_VARIANCE] = tempSum / RxInterarrivalTimes.size();

	//TX_RX_BYTE_RATIO
	featureSet[TX_RX_BYTE_RATIO] = TxTotalBytes / RxTotalBytes;
}

//The actual classification. Where all the magic happens
void Classify()
{
	int nPts = 0;
	ANNpointArray dataPts;
	ANNpoint queryPt;

	ANNidxArray	nnIdx;
	ANNdistArray dists;
	ANNkd_tree *kdTree;

	queryPt = annAllocPt(DIM);
	dataPts = annAllocPts(maxPts, DIM);
	nnIdx = new ANNidx[k];
	dists = new ANNdist[k];

	kdTree = new ANNkd_tree(
			dataPts,
			nPts,
			DIM);

	kdTree->annkSearch(
			queryPt,
			k,
			nnIdx,
			dists,
			eps);

	cout << "NN: Index Distance\n";

	for (uint i = 0; i < k; i++)
	{
		dists[i] = sqrt(dists[i]);
		cout << i << " " << nnIdx[i] << " " << dists[i] << "\n";
		delete [] nnIdx;
		delete [] dists;
		delete kdTree;
		annClose();
	}

}

//Campares two MAC addresses. Returns true if they're identical
bool CompareEthAddresses(u_int8_t *addr1, u_int8_t *addr2)
{
	for(uint i = 0; i < ETH_ALEN; i++)
	{
		if(addr1[i] != addr2[i])
		{
			return false;
		}
	}
	return true;
}


//Prints usage tips when you screw up the command line arguments
string Usage()
{
	string outputString = "Usage: ProtoType -i Dev -t ClassTimeout -s SourceMAC -d DestMAC\n";
	outputString += "Listen on the ethernet device, Dev\n";
	outputString += "Wait for ClassTimeout ms between classifications\n";
	outputString += "Use HW Address SourceMAC as source\n";
	outputString += "Use HW Address DestMAC as destination\n";

	outputString += "IE: ProtoType -i eth0 -t 5000 \n";

	return outputString;
}
