#include <Windows.h>
#include <iostream>

template <typename ... Arg>
uint64_t callHook(const Arg ... args) {
    void *hookFunction = GetProcAddress(LoadLibrary(L"win32u.dll"), "NtDxgkGetTrackedWorkloadStatistics");

    printf("Function addres %p", hookFunction);

    auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hookFunction);

    return func(args ...);
}

int main(){
    callHook();

    return 0;
}

