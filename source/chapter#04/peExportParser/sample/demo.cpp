#include <Windows.h>

extern "C" __declspec(dllexport) void func01()
{
    MessageBoxA(NULL, "Hello from func01!", "DLL Function", MB_OK);
}

extern "C" __declspec(dllexport) void func02()
{
    MessageBoxA(NULL, "Hello from func02!!", "DLL Function", MB_OK);
}

extern "C" __declspec(dllexport) void func03()
{
    MessageBoxA(NULL, "Hello from func03...!?", "DLL Function", MB_OK);
}