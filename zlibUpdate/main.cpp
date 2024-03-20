#include "fose/fose/PluginAPI.h"
#include "nvse/PluginAPI.h"
#include "zlib.h"

#pragma comment(lib, "zlibstat.lib")

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

static void SafeWrite32(UInt32 addr, UInt32 data) {
	UInt32	oldProtect;

	VirtualProtect((void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	*((UInt32*)addr) = data;
	VirtualProtect((void*)addr, 4, oldProtect, &oldProtect);
}

void SafeWrite16(UInt32 addr, UInt32 data) {
	UInt32	oldProtect;

	VirtualProtect((void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	*((UInt16*)addr) = data;
	VirtualProtect((void*)addr, 4, oldProtect, &oldProtect);
}

template <typename T>
DECLSPEC_NOINLINE void ReplaceCall(UInt32 jumpSrc, T jumpTgt) {
	SafeWrite32(jumpSrc + 1, UInt32(jumpTgt) - jumpSrc - 1 - 4);
}

static int __cdecl inflateInit_Ex(z_streamp strm, const char* version, int stream_size) {
	return inflateInit2_(strm, 15, ZLIB_VERSION, stream_size);
}

constexpr UInt32 zLibAllocSize = 0x1C08;


#ifdef FO3
void SafeWrite8(UInt32 addr, UInt32 data) {
	UInt32	oldProtect;

	VirtualProtect((void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	*((UInt8*)addr) = data;
	VirtualProtect((void*)addr, 4, oldProtect, &oldProtect);
}

void PatchMemoryNop(ULONG_PTR Address, SIZE_T Size) {
	DWORD d = 0;
	VirtualProtect((LPVOID)Address, Size, PAGE_EXECUTE_READWRITE, &d);

	for (SIZE_T i = 0; i < Size; i++)
		*(volatile BYTE*)(Address + i) = 0x90; //0x90 == opcode for NOP

	VirtualProtect((LPVOID)Address, Size, d, &d);

	FlushInstructionCache(GetCurrentProcess(), (LPVOID)Address, Size);
}

EXTERN_DLL_EXPORT bool FOSEPlugin_Query(const FOSEInterface* fose, PluginInfo* info) {
	info->infoVersion = PluginInfo::kInfoVersion;
	info->name = "zlib";
	info->version = 131;

	return true;
}

EXTERN_DLL_EXPORT bool FOSEPlugin_Load(FOSEInterface* nvse) {
	if (!nvse->isEditor) {
		ReplaceCall(0x4477A4, inflateInit_Ex); // TESFile::DecompressCurrentForm
		ReplaceCall(0xBCBE88, inflateInit_Ex); // CompressedArchiveFile::CompressedArchiveFile

		// Inflate
		ReplaceCall(0x44780E, inflate); // TESFile::DecompressCurrentForm
		ReplaceCall(0xBCA208, inflate); // CompressedArchiveFile::CompressedArchiveFile

		// End
		for (UInt32 uiAddr : { 0x4477B5, 0x447834, 0x447845, 0x44788F })
			ReplaceCall(uiAddr, inflateEnd); // TESFile::DecompressCurrentForm

		for (UInt32 uiAddr : { 0xBCA0F2, 0xBCA264, 0xBCBE9B })
			ReplaceCall(uiAddr, inflateEnd); // CompressedArchiveFile::~CompressedArchiveFile, CompressedArchiveFile::StandardReadF

		SafeWrite16(0xBCBE34, zLibAllocSize);	// Increase allocation size
	}
	else {
		ReplaceCall(0x4E32D8, inflateInit_Ex); // TESFile::DecompressCurrentForm
		ReplaceCall(0xB552D8, inflateInit_Ex); // CompressedArchiveFile::CompressedArchiveFile

		// Inflate
		ReplaceCall(0x4E3350, inflate); // TESFile::DecompressCurrentForm
		ReplaceCall(0xB52E98, inflate); // CompressedArchiveFile::CompressedArchiveFile

		// End
		for (UInt32 uiAddr : { 0x4E32E9, 0x4E33DC, 0x4E3387, 0x4E3376 })
			ReplaceCall(uiAddr, inflateEnd); // TESFile::DecompressCurrentForm

		for (UInt32 uiAddr : { 0xB52D82, 0xB52EF4, 0xB552EB })
			ReplaceCall(uiAddr, inflateEnd); // CompressedArchiveFile::~CompressedArchiveFile, CompressedArchiveFile::StandardReadF

		SafeWrite16(0xB55284, zLibAllocSize); // Increase allocation size

		// GECK Exclusive
		// Remove record compression
		PatchMemoryNop(0x57A448, 5); // TESNPC
		SafeWrite8(0x57A448, 0xC3);

		PatchMemoryNop(0x61912D, 5); // TESObjectLAND
	}

	return true;
}
#else
EXTERN_DLL_EXPORT bool NVSEPlugin_Query(const NVSEInterface* nvse, PluginInfo* info) {
	info->infoVersion = PluginInfo::kInfoVersion;
	info->name = "zlib";
	info->version = 131;

	return true;
}

EXTERN_DLL_EXPORT bool NVSEPlugin_Load(NVSEInterface* nvse) {
	if (!nvse->isEditor) {
		ReplaceCall(0x4742AC, inflateInit_Ex); // TESFile::DecompressCurrentForm
		ReplaceCall(0xAFC537, inflateInit_Ex); // CompressedArchiveFile::CompressedArchiveFile

		// Inflate
		ReplaceCall(0x47434F, inflate); // TESFile::DecompressCurrentForm
		ReplaceCall(0xAFC1F4, inflate); // CompressedArchiveFile::CompressedArchiveFile

		// End
		for (UInt32 uiAddr : { 0x4742CA, 0x474388, 0x4743D5, 0x474419 })
			ReplaceCall(uiAddr, inflateEnd); // TESFile::DecompressCurrentForm

		for (UInt32 uiAddr : { 0xAFC00E, 0xAFC21B, 0xAFC552 })
			ReplaceCall(uiAddr, inflateEnd); // CompressedArchiveFile::CompressedArchiveFile, CompressedArchiveFile::StandardReadF

		SafeWrite16(0xAFC4A2, zLibAllocSize);	// Increase allocation size
	}
	else {
		ReplaceCall(0x4DFB34, inflateInit_Ex); // TESFile::DecompressCurrentForm
		ReplaceCall(0x8AAF17, inflateInit_Ex); // CompressedArchiveFile::CompressedArchiveFile

		// Inflate
		ReplaceCall(0x4DFB9E, inflate); // TESFile::DecompressCurrentForm
		ReplaceCall(0x8AABD4, inflate); // CompressedArchiveFile::CompressedArchiveFile

		// End
		for (UInt32 uiAddr : { 0x4DFB45, 0x4DFC1F, 0x4DFBD5, 0x4DFBC4 })
			ReplaceCall(uiAddr, inflateEnd); // TESFile::DecompressCurrentForm

		for (UInt32 uiAddr : { 0x8AA9EE, 0x8AABFB, 0x8AAF32 })
			ReplaceCall(uiAddr, inflateEnd); // CompressedArchiveFile::~CompressedArchiveFile, CompressedArchiveFile::StandardReadF

		SafeWrite16(0x8AAE82, zLibAllocSize); // Increase allocation size
	}

	return true;
}
#endif