//============================================================================
// Name        : ProtoType.h
// Author      : AltF4
// Copyright   : GNU GPL v3
// Description : Point class that encapsulates an ANN point and classification
//============================================================================

#define DIM 9

#include "Point.h"


Point::Point()
{
	annPoint = annAllocPt(DIM);
	protocol = 0;
}

Point::~Point()
{
	annDeallocPt(annPoint);

}
