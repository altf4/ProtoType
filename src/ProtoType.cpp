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

using namespace std;

uint classificationTimeout = 0;
bool isTraining;
char *dataFilePath;

int main (int argc, char **argv)
{
	int c;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	pthread_t classificationThread, trainingThread;

	signal(SIGINT,WriteDataPointsToFile);

	while ((c = getopt (argc, argv, ":i:tcm:d:s:")) != -1)
	{
		switch (c)
		{
			case 'i':
			{
				dev = optarg;
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
				dataFilePath = optarg;
				break;
			}
			case 'c':
			{
				isTraining = false;
				dataFilePath = optarg;
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
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_loop(handle, 0, PacketHandler, NULL);

	return 0;
}

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	packet_t thisPacket;

	thisPacket.timestamp = header->ts.tv_sec;
	thisPacket.len = header->len;
	memcpy( thisPacket.eth_hdr, packet, ETH_ALEN);

	packetlist.push_back(thisPacket);
}

void *ClassificationLoop(void *ptr)
{
	//Keep looping
	while(true)
	{
		sleep(classificationTimeout);

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

void LoadDataPointsFromFile(char* filePath)
{
	if(filePath == NULL)
	{
		cerr << "You entered an empty file path\n";
		cout << Usage();
		exit(1);
	}
	string line;

	//Creates an instance of ofstream, and opens example.txt
	ifstream dataFile(filePath);
	getline(dataFile,line);




	// Close the file stream explicitly
	dataFile.close();


}

void WriteDataPointsToFile(int sig)
{
	if(dataFilePath == NULL)
	{
		cerr << "You entered an empty file path. :(\n";
		cout << Usage();
		exit(1);
	}
	string line;

	//Creates an instance of ofstream, and opens example.txt
	ofstream dataFile(dataFilePath);

	//TODO: Do the actual writing here

	dataFile.close();
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

void CalculateFeatureSet()
{

}

void Classify()
{

}

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

string Usage()
{
	string outputString = "Usage: ProtoType -i Dev -t ClassTimeout -s SourceMAC -d DestMAC\n";
	outputString += "Listen on the ethernet device, Dev\n";
	outputString += "Wait for ClassTimeout ms between classifications\n";
	outputString += "Wait for ClassTimeout ms between classifications\n";
	outputString += "Wait for ClassTimeout ms between classifications\n";

	outputString += "IE: ProtoType -i eth0 -t 5000 \n";

	return outputString;
}
