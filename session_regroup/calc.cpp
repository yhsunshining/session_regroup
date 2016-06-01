#include "stdafx.h"
#include "calc.h"


calc::calc()
{
}


calc::~calc()
{
}

u_int16_t calc::ntohs(u_int16_t nshort){
	u_int16_t low = nshort & 0x00ff;
	nshort = nshort >> 8;
	nshort = nshort | (low << 8);
	return nshort;
}

u_int16_t calc::htons(u_int16_t hshort){
	return ntohs(hshort);
}

u_int32_t calc::ntohi(u_int32_t nint){
	u_int byte1 = (nint & 0xff000000) >> 24;
	u_int byte2 = (nint & 0x00ff0000) >> 8;
	u_int byte3 = (nint & 0x0000ff00) << 8;
	u_int byte4 = (nint & 0x000000ff) << 24;
	return byte1 | byte2 | byte3 | byte4;
}