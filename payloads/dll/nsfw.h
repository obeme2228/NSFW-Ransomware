#pragma once

#include <windows.h>

#ifdef BLU3_EXPORTS
#define BLU3_API __declspec(dllexport)
#else
#define BLU3_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif
    BLU3_API int fnblu3(void);
    BLU3_API BOOL ForcePopupReadmeHta();
    BLU3_API BOOL ForcePopupReadmeHtaEx(const wchar_t* htaPath);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
class BLU3_API Cblu3 {
public:
    Cblu3();
};
#endif
