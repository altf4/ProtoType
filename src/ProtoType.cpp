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
#include "Point.h"
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <math.h>
#include <ANN/ANN.h>
#include <netinet/ether.h>

using namespace std;

uint classificationTimeout = 200;
bool isTraining = true;
string dataFilePath;

//The list of data points, with classification
vector <Point*> dataPointsWithClass;
ANNpointArray dataPts;
ANNpointArray normalizedDataPts;

//The feature set in ANN point format
ANNpoint queryPt = annAllocPt(DIM);

struct timeval TxFirstPacketArrivalTime;
struct timeval RxFirstPacketArrivalTime;

double classification;

//Right now, just equals TCP/UDP port
int protocol;

pthread_mutex_t packetListMutex = PTHREAD_MUTEX_INITIALIZER;

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
				struct ether_addr *temp = ether_aton(optarg);
				if(temp != NULL)
				{
					memcpy(&etherRxAddress, temp, sizeof(ether_addr));
				}
				else
				{
					cerr << "You entered a bad Rx hw address.\n";
					cout << Usage();
				}
				break;
			}
			case 'd':
			{
				struct ether_addr *temp = ether_aton(optarg);
				if(temp != NULL)
				{
					memcpy(&etherTxAddress, temp, sizeof(ether_addr));
				}
				else
				{
					cerr << "You entered a bad Tx hw address.\n";
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


	//Initialize some vars
	RxLastPacketArrivalTime.tv_sec = 0;
	RxLastPacketArrivalTime.tv_usec = 0;
	TxLastPacketArrivalTime.tv_sec = 0;
	TxLastPacketArrivalTime.tv_usec = 0;

	//Start listening for packets
	handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
	pcap_loop(handle, -1, PacketHandler, NULL);

	return 0;
}

//Gets called each time a packet arrives.
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	packet_t thisPacket;

	thisPacket.timestamp = header->ts;
	thisPacket.len = header->len;

	memcpy( &thisPacket.eth_dest_addr, packet, ETH_ALEN);
	memcpy( &thisPacket.eth_src_addr, packet + ETH_ALEN, ETH_ALEN);

	pthread_mutex_lock( &packetListMutex );
	packetlist.push_back(thisPacket);
	pthread_mutex_unlock( &packetListMutex );

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
		pthread_mutex_lock( &packetListMutex );
		for(uint i = 0; i < packetlist.size(); i++)
		{
			CalculateDependencyVariables(packetlist[i]);
		}
		packetlist.clear();
		pthread_mutex_unlock( &packetListMutex );

		CalculateFeatureSet();
		NormalizeDataPoints();
		Classify();

	}

	//Shouldn't get here. This is just to get rid of the compiler warning.
	return NULL;
}

void NormalizeDataPoints()
{
	//Find the max values for each feature
	for(int i = 0; i < DIM; i++)
	{
		if(featureSet[i] > maxFeatureValues[i])
		{
			maxFeatureValues[i] = featureSet[i];
		}
	}

	//Normalize the suspect points

	//If the max is 0, then there's no need to normalize! (Plus it'd be a div by zero)
	for(int i = 0;i < DIM; i++)
	{
		if(maxFeatureValues[0] != 0)
		{
			queryPt[i] = (double)(featureSet[i] / maxFeatureValues[i]);
		}
	}


	//Normalize the data points
	//Foreach data point
	for(int j = 0; j < DIM; j++)
	{
		//Foreach feature within the data point
		for(int i=0;i < nPts;i++)
		{
			if(maxFeatureValues[j] != 0)
			{
				normalizedDataPts[i][j] = (double)((dataPts[i][j] / maxFeatureValues[j]));
			}
			else
			{
				cerr << "Max Feature Value for feature " << (i+1) << " is 0!\n";
				break;
			}
		}
	}
}

//On training mode, reclassify data points periodically
void *TrainingLoop(void *ptr)
{
	//Keep looping
	while(true)
	{
		sleep(classificationTimeout);

		//For the new packet's we've accumulated, recalculate
		//	Dependency variables
		pthread_mutex_lock( &packetListMutex );
		for(uint i = 0; i < packetlist.size(); i++)
		{
			CalculateDependencyVariables(packetlist[i]);
		}
		packetlist.clear();
		pthread_mutex_unlock( &packetListMutex );

		CalculateFeatureSet();
		NormalizeDataPoints();
	}

	//Shouldn't get here. This is just to get rid of the compiler warning.
	return NULL;
}

//Called in classification mode to retrieve a stored data set
//	Writes into dataPointsWithClass, normalizedDataPts, and dataPts
void LoadDataPointsFromFile(string filePath)
{
	ifstream myfile (dataFilePath.data());
	string line;
	int i = 0;
	//Count the number of data points for allocation
	if (myfile.is_open())
		{
		while (!myfile.eof())
		{
			if(myfile.peek() == EOF)
			{
				break;
			}
			getline(myfile,line);
			i++;
		}
	}
	else
	{
		cerr << "Unable to open file.\n";
	}
	myfile.close();
	maxPts = i;

	//Open the file again, allocate the number of points and assign
	myfile.open(dataFilePath.data(), ifstream::in);
	dataPts = annAllocPts(maxPts, DIM);
	normalizedDataPts = annAllocPts(maxPts, DIM);

	if (myfile.is_open())
	{
		i = 0;

		while (!myfile.eof() && (i < maxPts))
		{
			if(myfile.peek() == EOF)
			{
				break;
			}

			dataPointsWithClass.push_back(new Point());

			for(int j = 0;j < DIM;j++)
			{
				getline(myfile,line,' ');
				double temp = strtod(line.data(), NULL);

				dataPointsWithClass[i]->annPoint[j] = temp;
				dataPts[i][j] = temp;

				//Set the max values of each feature. (Used later in normalization)
				if(temp > maxFeatureValues[j])
				{
					maxFeatureValues[j] = temp;
				}
			}
			getline(myfile,line);
			dataPointsWithClass[i]->protocol = atoi(line.data());
			i++;
		}
		nPts = i;
	}
	else cerr << "Unable to open file.\n";

	myfile.close();
}

//Called on training mode to save data to file
void WriteDataPointsToFile(int sig)
{
	if( isTraining )
	{
		ofstream myfile (dataFilePath.data(), ios::app);

		if (myfile.is_open())
		{
			for(int i=0; i < DIM; i++)
			{
				myfile << featureSet[i] << " ";
			}
			myfile << protocol;
			myfile << "\n";
		}
		else
		{
			cerr << "Unable to open file.\n";
		}
		myfile.close();
	}
	exit(1);
}
//Calculate the set of dependency variables for this new packet
void CalculateDependencyVariables(packet_t packet)
{
	bool isRx;

	if( CompareEthAddresses( &packet.eth_dest_addr , &etherTxAddress) )
	{
		isRx = false;
	}
	else if( CompareEthAddresses( &packet.eth_src_addr , &etherRxAddress) )
	{
		isRx = true;
	}


	//Calculate Dependency Variables
	if(isRx)
	{
		RxTotalBytes += packet.len;
		RxTotalPackets++;

		//If this is not our first packet...
		if(RxLastPacketArrivalTime.tv_sec != 0)
		{
			struct timeval timeDiff;
			timeval_subtract(&timeDiff, &packet.timestamp, &RxLastPacketArrivalTime);
			double timeDiffDouble = timeDiff.tv_sec + ( (double)timeDiff.tv_usec /  1000000.0);

			RxInterarrivalTimes.push_back( timeDiffDouble );
		}
		//Our first packet
		else
		{
			RxFirstPacketArrivalTime = packet.timestamp;
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
		if(TxLastPacketArrivalTime.tv_sec != 0)
		{
			struct timeval timeDiff;
			timeval_subtract(&timeDiff, &packet.timestamp, &TxLastPacketArrivalTime);
			double timeDiffDouble = timeDiff.tv_sec + ( (double)timeDiff.tv_usec /  1000000.0);

			TxInterarrivalTimes.push_back( timeDiffDouble );

		}
		//Our first packet
		else
		{
			TxFirstPacketArrivalTime = packet.timestamp;
			TxLastPacketArrivalTime = packet.timestamp;
		}
		TxPacketSizes.push_back(packet.len);
		TxLastPacketArrivalTime = packet.timestamp;
	}

}

//Update the feature set for new evidence that's come in
void CalculateFeatureSet()
{
	//Packet size mean
	if( TxTotalPackets != 0 )
	{
		featureSet[TX_PACKET_SIZE_MEAN] = TxTotalBytes / TxTotalPackets;
	}
	else
	{
		featureSet[TX_PACKET_SIZE_MEAN] = 0;
	}
	if( RxTotalPackets != 0 )
	{
		featureSet[RX_PACKET_SIZE_MEAN] = RxTotalBytes / RxTotalPackets;
	}
	else
	{
		featureSet[RX_PACKET_SIZE_MEAN] = 0;
	}


	//Tx Packet size variance
	double tempSum = 0;
	if (TxPacketSizes.size() > 0)
	{
		for(uint i = 0; i < TxPacketSizes.size(); i++)
		{
			tempSum += pow( (TxPacketSizes[i] - featureSet[TX_PACKET_SIZE_MEAN]), 2);
		}
		featureSet[TX_PACKET_SIZE_VARIANCE] = tempSum / TxPacketSizes.size();
	}
	else
	{
		featureSet[TX_PACKET_SIZE_VARIANCE] = 0;
	}


	//Rx Packet size variance
	tempSum = 0;
	if (RxPacketSizes.size() > 0)
	{
		for(uint i = 0; i < RxPacketSizes.size(); i++)
		{
			tempSum += pow( (RxPacketSizes[i] - featureSet[RX_PACKET_SIZE_MEAN]), 2);
		}
		featureSet[RX_PACKET_SIZE_VARIANCE] = tempSum / RxPacketSizes.size();
	}
	else
	{
		featureSet[RX_PACKET_SIZE_VARIANCE] = 0;
	}

	//TX_PACKET_INTERARRIVAL_MEAN
	if( TxTotalPackets > 1 )
	{
		struct timeval timeDiff;
		timeval_subtract(&timeDiff, &TxLastPacketArrivalTime, &TxFirstPacketArrivalTime);

		double timeDiffDouble = timeDiff.tv_sec + ( (double)timeDiff.tv_usec /  1000000.0);

		featureSet[TX_PACKET_INTERARRIVAL_MEAN] =  timeDiffDouble / TxTotalPackets;
	}
	else
	{
		featureSet[TX_PACKET_INTERARRIVAL_MEAN] = 0;
	}

	//RX_PACKET_INTERARRIVAL_MEAN
	if( RxTotalPackets > 1 )
	{
		struct timeval timeDiff;
		timeval_subtract(&timeDiff, &RxLastPacketArrivalTime, &RxFirstPacketArrivalTime);

		double timeDiffDouble = timeDiff.tv_sec + ( (double)timeDiff.tv_usec /  1000000.0);

		featureSet[RX_PACKET_INTERARRIVAL_MEAN] =  timeDiffDouble / RxTotalPackets;
	}
	else
	{
		featureSet[RX_PACKET_INTERARRIVAL_MEAN] = 0;
	}

	//TX_PACKET_INTERARRIVAL_VARIANCE
	tempSum = 0;
	if( TxInterarrivalTimes.size() > 0 )
	{
		for(uint i = 0; i < TxInterarrivalTimes.size(); i++)
		{
			tempSum += pow( TxInterarrivalTimes[i] - featureSet[TX_PACKET_INTERARRIVAL_MEAN], 2);
		}
		featureSet[TX_PACKET_INTERARRIVAL_VARIANCE] = tempSum / TxInterarrivalTimes.size();	}
	else
	{
		featureSet[TX_PACKET_INTERARRIVAL_VARIANCE] = 0;
	}


	//RX_PACKET_INTERARRIVAL_VARIANCE
	tempSum = 0;
	if( RxInterarrivalTimes.size() > 0 )
	{
		for(uint i = 0; i < RxInterarrivalTimes.size(); i++)
		{
			tempSum += pow( RxInterarrivalTimes[i] - featureSet[RX_PACKET_INTERARRIVAL_MEAN], 2);
		}
		featureSet[RX_PACKET_INTERARRIVAL_VARIANCE] = tempSum / RxInterarrivalTimes.size();
	}
	else
	{
		featureSet[RX_PACKET_INTERARRIVAL_VARIANCE] = 0;
	}

	//TX_RX_BYTE_RATIO
	if( RxTotalBytes != 0 )
	{
		featureSet[TX_RX_BYTE_RATIO] = (double) TxTotalBytes / (double) RxTotalBytes;
	}
	else
	{
		featureSet[TX_RX_BYTE_RATIO] = 0;
	}
}

//The actual classification. Where all the magic happens
void Classify()
{

	ANNidxArray	nnIdx;
	ANNdistArray dists;
	ANNkd_tree *kdTree;

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

	//Unsquare the distances and print
	for (uint i = 0; i < k; i++)
	{
		dists[i] = sqrt(dists[i]);
		cout << i << " " << nnIdx[i] << " " << dists[i] << " protocol: " <<  dataPointsWithClass[nnIdx[i]]->protocol <<  "\n";
	}

	protocolCountTable protocolCount;
	for (uint i = 0; i < k; i++)
	{
		//TODO: Make a more sophisticated final guess than mere plurality vote
		protocolCount[dataPointsWithClass[nnIdx[i]]->protocol]++;
	}

	int protocolWinner = 0;
	int highestVotes = 0;
	//Go through and see which protocol had the most...
	for (protocolCountTable::iterator it = protocolCount.begin();
				it != protocolCount.end(); it++ )
	{
		if ( it->second > highestVotes)
		{
			highestVotes = it->second;
			protocolWinner = it->first;
		}
	}

	classification = protocolWinner;
	cout << "Classified as: " << classification << "\n";

	delete [] nnIdx;
	delete [] dists;
	delete kdTree;
	annClose();
}

//Campares two MAC addresses. Returns true if they're identical
bool CompareEthAddresses(struct ether_addr *addr1, struct ether_addr *addr2)
{
	for(uint i = 0; i < ETH_ALEN; i++)
	{
		if(addr1->ether_addr_octet[i] != addr2->ether_addr_octet[i])
		{
			return false;
		}
	}
	return true;
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
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
