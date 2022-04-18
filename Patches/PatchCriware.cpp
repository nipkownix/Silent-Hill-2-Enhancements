#include <windows.h>
#include "Criware\criware.h"
#include "Logging\Logging.h"
#include "External/Hooking.Patterns/Hooking.Patterns.h"
#include "External/injector/include/injector/injector.hpp"
#include "Common/Utils.h"

void PatchCriware()
{
	// ADXT_StartAfs pattern. We use this as a base since it is the lowest memory address.
	auto pattern = hook::pattern("83 EC ? 53 56 8B 74 24 ? 57 85 F6 75 ? 68 ? ? ? ? E8 ? ? ? ? 83 C4");
	if (pattern.size() != 1)
	{
		Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
		return;
	}

	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(9600), ADXF_LoadPartitionNw, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(9968), ADXF_GetPtStat, 6);

	WriteCalltoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14528), ADXWIN_SetupDvdFs, 5);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14656), ADXWIN_ShutdownDvdFs, 5);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14704), ADXWIN_SetupSound, 6);

	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14800), ADXFIC_Create, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14864), ADXFIC_GetNumFiles, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14960), ADXFIC_GetFileName, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(14816), ADXFIC_Destroy, 6);

	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(16112), ADXM_SetupThrd, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(16688), ADXM_ExecMain, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(16720), ADXM_ShutdownThrd, 6);

	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(0), ADXT_StartAfs, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(224), ADXT_StartFname, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(752), ADXT_Create, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(2080), ADXT_Stop, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(2208), ADXT_GetStat, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(3552), ADXT_SetOutVol, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(17952), ADXT_Init, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(18176), ADXT_Finish, 6);

	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(5696), AIXP_Init, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(5824), AIXP_Create, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(6336), AIXP_Destroy, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(6592), AIXP_StartFname, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(6752), AIXP_Stop, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(6880), AIXP_GetStat, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(6896), AIXP_GetAdxt, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(6944), AIXP_SetLpSw, 6);
	WriteJMPtoMemory((BYTE*)pattern.count(1).get(0).get<uint32_t*>(7776), AIXP_ExecServer, 6);
}
