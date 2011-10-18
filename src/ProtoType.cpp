//============================================================================
// Name        : ProtoType.cpp
// Author      : AltF4
// Copyright   : GNU GPL v3
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <iostream>
#include "ProtoType.h"

using namespace std;

int main (int argc, char **argv)
{
	int c;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];;
	pcap_t *handle;

	while ((c = getopt (argc, argv, ":i:")) != -1)
	{
		switch (c)
		{
			case 'i':
			{
				dev = optarg;
				break;
			}
			case '?':
			{
				if (isprint (optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;

			}
			default:
			{
				return 1;
			}
		}
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	cout << "Got C" << endl;

	pcap_loop(handle, 0, PacketHandler, NULL);

	return 0;
}

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	cout << "Got a packet!\n";

}
