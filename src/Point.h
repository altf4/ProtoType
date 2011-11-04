//============================================================================
// Name        : ProtoType.h
// Author      : AltF4
// Copyright   : GNU GPL v3
// Description : Point class that encapsulates an ANN point and classification
//============================================================================

#ifndef POINT_H_
#define POINT_H_

#include <ANN/ANN.h>

class Point
{
public:
	ANNpoint annPoint;

	//Right now, just equals TCP/UDP port
	int protocol;

	Point();
	~Point();

};

#endif /* POINT_H_ */
