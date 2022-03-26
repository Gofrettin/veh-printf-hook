#include <iostream>
#include <windows.h>
PVOID veh_handle = nullptr;
DWORD old = 0;
void print_woo() {
    std::cout << "woo" << "\n";
}

// veh handler function. this is the function that will allow us to "jump" to our print_woo function.

LONG WINAPI veh_handler(EXCEPTION_POINTERS *exception_info) {
    // check if we get a page violation.
    if(exception_info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        // check if we're at the right address for the function we want to hook
        if(exception_info->ContextRecord->Eip == (uintptr_t)printf) {
            // change the instruction pointer to point to our function.
            exception_info->ContextRecord->Eip = (uintptr_t)print_woo;
        }
        // enable single stepping mode
        exception_info->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // we enabled single stepping mode so that we can set the page_guard flag on the printf page
    // every time it goes to a new address in memory. this is because page_guard is disabled
    // after "stepping"
    if(exception_info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        DWORD buff_old;
        VirtualProtect((LPVOID)printf, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &buff_old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool same_page() {
    // check if our function is in the same page as printf. if it is we cannot hook it.
    MEMORY_BASIC_INFORMATION mem_basic_info1;
    if(!VirtualQuery((const uint8_t*)printf, &mem_basic_info1, sizeof(mem_basic_info1))) {
        return true;
    }
    MEMORY_BASIC_INFORMATION mem_basic_info2;
    if(!VirtualQuery((const uint8_t*)print_woo, &mem_basic_info2, sizeof(mem_basic_info2))) {
        return true;
    }
    if(mem_basic_info1.BaseAddress == mem_basic_info2.BaseAddress) {
        return true;
    }

    return false;
}


bool hook_func() {
    if(same_page()) {
        return false;
    }
    // add our exception handler.
    veh_handle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)veh_handler);
    // check if adding our exception handler went well, if it did then enable the page_guard flag in the page
    // printf is in.
    if(veh_handle && VirtualProtect((LPVOID)printf, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old)) {
        return true;
    }
    return false;
}

int main() {
    // now have fun!
    if(!hook_func()) {
        printf("%s", "Wasn't able to hook printf.\n");
        return 0;
    }
    printf("%s", "Hooked.");
    printf("%s", "Hooked x2.");
    printf("%s", "Hooked x3");
    return 0;
}
