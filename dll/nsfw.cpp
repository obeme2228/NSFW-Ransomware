// blu3.cpp : Defines the exported functions for the DLL.
//

#define BLU3_EXPORTS
#include "pch.h"
#include "framework.h"
#include "blu3.h"
#include <windows.h>
#include <shellapi.h>

// This is an example of an exported variable
BLU3_API int nblu3 = 0;

// This is an example of an exported function.
BLU3_API int fnblu3(void)
{
    return 0;
}

// Force pop-up of readme.hta from a hardcoded path
BLU3_API BOOL ForcePopupReadmeHta()
{
    const wchar_t* htaPath = L"..\\..\\..\\..\\..\\..\\source\\repos\\readme.hta";
    HINSTANCE result = ShellExecuteW(
        NULL,
        L"open",
        htaPath,
        NULL,
        NULL,
        SW_SHOWNORMAL
    );
    return ((INT_PTR)result > 32);
}

// Force pop-up of a specified .hta file
BLU3_API BOOL ForcePopupReadmeHtaEx(const wchar_t* htaPath)
{
    if (!htaPath) return FALSE;
    HINSTANCE result = ShellExecuteW(
        NULL,
        L"open",
        htaPath,
        NULL,
        NULL,
        SW_SHOWNORMAL
    );
    return ((INT_PTR)result > 32);
}

#ifdef __cplusplus
Cblu3::Cblu3() {}
#endif
