#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "Patches.h"
#include "Common\Utils.h"
#include "Logging\Logging.h"
#include <Common/FileSystemHooks.h>
#include "External/Hooking.Patterns/Hooking.Patterns.h"

bool CaptureThreads = false;

int (*orgADXThreadStarter)(const void* a1);
int __cdecl ADXThreadStarter(const void* a1)
{
    CaptureThreads = true;

    int SetupADXThreads = orgADXThreadStarter(a1);

    CaptureThreads = false;

    return SetupADXThreads;
}

void AudioDeadlockFix()
{
	using namespace hook;

	// Hook functions that create ADX threads
	DWORD ADXThreadAddr;
	{
		auto ADXPattern = pattern("E8 ? ? ? ? 83 C4 0C E8 ? ? ? ? BE ? ? ? ?").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXThreadAddr = reinterpret_cast<DWORD>(ADXPattern.get_first(0));
	}

	// Shared
	int32_t jmpAddress = 0;
	memcpy(&jmpAddress, (void*)(ADXThreadAddr + 1), sizeof(jmpAddress));

	orgADXThreadStarter = decltype(orgADXThreadStarter)(jmpAddress + ADXThreadAddr + 5);
	WriteCalltoMemory((BYTE*)ADXThreadAddr, ADXThreadStarter);

	// Not sure if we need to hook this JMP too, but might as well, just to be safe
	DWORD ADXThreadAddr2;
	{
		auto ADXPattern = pattern("C7 44 24 04 00 00 00 00 E9 ? ? ? ? 90 90 90 E9").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXThreadAddr2 = reinterpret_cast<DWORD>(ADXPattern.get_first(8));
	}

	WriteJMPtoMemory((BYTE*)ADXThreadAddr2, ADXThreadStarter);

    // Disable original ADX thread code
	DWORD ADXjmp1Addr;
	{
		auto ADXPattern = pattern("75 ? E8 ? ? ? ? E8 ? ? ? ? 6A ? 6A").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXjmp1Addr = reinterpret_cast<DWORD>(ADXPattern.get_first(0));
	}
	
	DWORD ADXjmp2Addr;
	{
		auto ADXPattern = pattern("74 ? E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 C0").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXjmp2Addr = reinterpret_cast<DWORD>(ADXPattern.get_first(0));
	}

	DWORD ADXjmp3Addr;
	{
		auto ADXPattern = pattern("75 ? E8 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? E8").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXjmp3Addr = reinterpret_cast<DWORD>(ADXPattern.get_first(0));
	}

    Logging::Log() << "Disabling original ADX thread code...";
    UpdateMemoryAddress((void*)ADXjmp1Addr, "\xEB\x05", 2); // 0x005605A9
    UpdateMemoryAddress((void*)ADXjmp2Addr, "\xEB\x05", 2); // 0x00560468
    UpdateMemoryAddress((void*)ADXjmp3Addr, "\xEB\x05", 2); // 0x00560546
	
	// Change ADX CMP values (part of Steam006's patches)
	DWORD ADXcmp1Addr;
	{
		auto ADXPattern = pattern("81 FE ? ? ? ? 7C ? 81 FE ? ? ? ? 75 ? 68").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXcmp1Addr = reinterpret_cast<DWORD>(ADXPattern.get_first(2));
	}

	DWORD ADXcmp2Addr;
	{
		auto ADXPattern = pattern("81 FE ? ? ? ? 75 ? 68 ? ? ? ? E8 ? ? ? ? 83 C4 ? A1").count(1);
		if (ADXPattern.size() != 1)
		{
			Logging::Log() << __FUNCTION__ " Error: failed to find memory address!";
			return;
		}
		ADXcmp2Addr = reinterpret_cast<DWORD>(ADXPattern.get_first(2));
	}

	Logging::Log() << "Updating ADX cmp values...";
    UpdateMemoryAddress((void*)ADXcmp1Addr, "\xC0\xC6\x2D\x00", 4); // 0x0055FA5F
    UpdateMemoryAddress((void*)ADXcmp2Addr, "\xC0\xC6\x2D\x00", 4); // 0x0055FA67

	// Hook threading functions
	InstallCreateThreadHooks();
	InstallSetThreadPriorityHooks();
	InstallSetThreadPriorityBoostHooks();
	InstallResumeThreadHooks();
}

