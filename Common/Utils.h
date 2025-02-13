#pragma once

#include <vector>
#include <Shldisp.h>

void *GetAddressOfData(const void *data, size_t len, DWORD step = 1);
void *GetAddressOfData(const void *data, size_t len, DWORD step, DWORD start, DWORD distance = 0x0FFFFFFF);
bool CheckMemoryAddress(void *dataAddr, void *dataBytes, size_t dataSize, bool WriteLog = true);
void *CheckMultiMemoryAddress(void *dataAddr10, void *dataAddr11, void *dataAddrDC, void *dataBytes, size_t dataSize);
DWORD SearchAndGetAddresses(DWORD dataAddr10, DWORD dataAddr11, DWORD dataAddrDC, const BYTE *dataBytes, size_t dataSize, int ByteDelta);
DWORD ReadSearchedAddresses(DWORD dataAddr10, DWORD dataAddr11, DWORD dataAddrDC, const BYTE *dataBytes, size_t dataSize, int ByteDelta);
void SearchAndLogAddress(DWORD SearchAddress);
bool UpdateMemoryAddress(void *dataAddr, const void *dataBytes, size_t dataSize);
bool WriteCalltoMemory(BYTE *dataAddr, const void *JMPAddr, DWORD count = 5);
bool WriteJMPtoMemory(BYTE *dataAddr, const void *JMPAddr, DWORD count = 5);
DWORD ReplaceMemoryBytes(void *dataSrc, void *dataDest, size_t size, DWORD start, DWORD distance, DWORD count = 0);
DWORD_PTR GetProcessMask();
void SetSingleCoreAffinity();
void SetDPIAware();
HMODULE SetAppTheme();
void SetWindowTheme(HWND hWnd);
void AddHandleToVector(HMODULE dll);
void UnloadAllModules();
DWORD ConvertFloat(float num);
HRESULT UnZipFile(BSTR sourceZip, BSTR destFolder);
bool GetModulePath(char *path, rsize_t size);
bool GetModulePath(wchar_t *path, rsize_t size);
bool GetSH2FolderPath(char *path, rsize_t size);
bool GetSH2FolderPath(wchar_t *path, rsize_t size);
bool CheckPathNameMatch(LPCSTR lpFileName1, LPCSTR lpFileName2);
void CopyReplaceSlash(char* DestStr, size_t Size, LPCSTR SrcStr);
BOOL GetAppsLightMode();
HMONITOR GetMonitorHandle();
void GetDesktopRes(LONG &screenWidth, LONG &screenHeight);
void GetDesktopRect(RECT &screenRect);
HRESULT GetSavedResolution(DWORD &Width, DWORD &Height);
HRESULT SaveResolution(DWORD Width, DWORD Height);
void LogDirectory();
