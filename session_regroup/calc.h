#pragma once
#include "def.h"
class calc
{
public:
	calc();
	~calc();
	u_int16_t ntohs(u_int16_t nshort);
	u_int16_t htons(u_int16_t hshort);
	u_int32_t ntohi(u_int32_t nint);
};

