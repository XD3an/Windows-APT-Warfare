#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

size_t ptr_msgboxa = 0;

void IATHook(char* module, const char* szHook_ApiName, size_t callback, size_t& ApiAddr)
{
    auto IATDir = getNtHdr(module)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto impModuleList = (IMAGE_IMPORT_DESCRIPTOR*)&module[IATDir.VirtualAddress];
    for (; impModuleList->Name; impModuleList++)
    {
        auto callViaArr = (IMAGE_THUNK_DATA*)&module[impModuleList->FirstThunk];
        auto ApiNamesArr = (IMAGE_THUNK_DATA*)&module[impModuleList->OriginalFirstThunk];
        for (int i = 0; ApiNamesArr[i].u1.Function; i++)
        {
            auto curr_impApi = (PIMAGE_IMPORT_BY_NAME)&module[ApiNamesArr[i].u1.Function];
            if (!strcmp(szHook_ApiName, (char*)curr_impApi->Name))
            {
                ApiAddr = callViaArr[i].u1.Function;
                callViaArr[i].u1.Function = callback;
                break;
            }
        }
    }
}

int main(int argc, char** argv)
{
    void (*ptr)(UINT, LPCSTR, LPCSTR, UINT) = [](UINT hwnd, LPCSTR lpText, LPCSTR lpTitle, UINT uType)
    {
        printf("[Hook] MessageBoxA(%i, \"%s\", \"%s\", %i)", hwnd, lpText, lpTitle, uType);
        ((UINT(*)(UINT, LPCSTR, LPCSTR, UINT))ptr_msgboxa)(hwnd, "MessageBoxA got hooked", "alert", uType);
    };
    IATHook((char*)GetModuleHandle(NULL), "MessageBoxA", (size_t)ptr, ptr_msgboxa);

    // try to call hooked function
    MessageBoxA(0, "IAT Hook Test", "title", 0);
    return 0;
}