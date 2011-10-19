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

using namespace std;

uint classificationTimeout = 0;

int main (int argc, char **argv)
{
	int c;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	pthread_t classificationThread;

	while ((c = getopt (argc, argv, ":i:t:")) != -1)
	{
		switch (c)
		{
			case 'i':
			{
				dev = optarg;
				break;
			}
			case 't':
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

	//Start the Classification Loop
	pthread_create( &classificationThread, NULL, ClassificationLoop, NULL);

	//Start listening for packets
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_loop(handle, 0, PacketHandler, NULL);

	return 0;
}

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//Pointers into the packet object for different TCP/IP layers
	char* ethernet, ip;
	//Reported (not measured) size of IP layer
	uint size_ip;

	//TODO: Determine whether this packet is Tx or Rx
	bool isRx = true;

	//TODO: Calculate dependency variables for this new packet
	if(isRx)
	{
		RxTotalBytes += header->len;
		RxTotalPackets++;
	}
	else
	{
		TxTotalBytes += header->len;
		TxTotalPackets++;
	}


}

void *ClassificationLoop(void *ptr)
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

string Usage()
{
	string outputString = "Usage: ProtoType -i Dev -t ClassTimeout\n";
	outputString += "Listen on the ethernet device, Dev\n";
	outputString += "Wait for ClassTimeout ms between classifications\n";
	outputString += "IE: ProtoType -i eth0 t 5000\n";

	return outputString;
}
