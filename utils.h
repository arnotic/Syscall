#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

	PTEB __fastcall getAddrTEB();
	DWORD __fastcall callSyscall();
	DWORD calcCrc32(DWORD crc, BYTE* pSrc, DWORD count);
	char* __fastcall bnultoa(DWORD dwnum, char* szdst); // NE MET PAS DE 0 A LA FIN POUR CHAINAGE EVENTUEL !
	char* __fastcall bnuqwtoa(unsigned __int64 qwnum, char* szdst);
	char* __fastcall bnqwtohexa(UINT64 qwnum, char* szdst);
	
#ifdef __cplusplus
}
#endif

#endif
#pragma once
