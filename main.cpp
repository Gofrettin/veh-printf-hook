#include <iostream>
#include <windows.h>
// function that we will "jump" to
void print_woo() {
    std::cout << "woo" << "\n";
}

// veh function. this is the function that will allow us to "jump" to our print_woo function.


LONG WINAPI veh(EXCEPTION_POINTERS *exception_info) {
    // check if we get a page violation.
    if(exception_info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        // check if we're at the right address for the function we want to hook
        if(exception_info->ContextRecord->Eip == reinterpret_cast<uintptr_t>(printf)) {
            // change the instruction pointer to point to our function.
            exception_info->ContextRecord->Eip = reinterpret_cast<uintptr_t>(print_woo);
        }
        // enable single stepping mode
        exception_info->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // we enabled single stepping mode so that we can set the page_guard flag on the printf page
    // every time it goes to a new address in memory. this is because page_guard is disabled
    // after "stepping"
    if(exception_info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        DWORD prot_buff;
        VirtualProtect(reinterpret_cast<PVOID>(printf), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &prot_buff);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    MEMORY_BASIC_INFORMATION printf_info;
    MEMORY_BASIC_INFORMATION printwoo_info;
    PVOID veh_handle;
    DWORD prot_buff;

    // check that the virtual queries we make go properly.
    if(!VirtualQuery(reinterpret_cast<const uintptr_t*>(printf), &printf_info, sizeof(printf_info))) { printf("Failed to query basic information with VirtualQuery.\nGLE(get last error) code: %i", GetLastError()); return 0; }
    if(!VirtualQuery(reinterpret_cast<const uintptr_t*>(print_woo), &printwoo_info, sizeof(printwoo_info))) { printf("%s", "Failed to query basic information with VirtualQuery.\nGLE(get last error) code: %i", GetLastError()); return 0;}
    
    // check if our function is in the same page as printf. if it is we cannot hook it.
    if(printf_info.BaseAddress == printwoo_info.BaseAddress) {
        printf("%s", "Cannot hook printf. Same mem page as printwoo.");
        return 0;
    }

    // add our veh.
    veh_handle = AddVectoredExceptionHandler(1, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(veh));
    
    // check if adding our exception handler went well, if it did then enable the pageguard flag in the mem page
    // printf is in.
    if(veh_handle == NULL) { printf("%s", "Failed to add vectored exception handler."); }
    if(!VirtualProtect(reinterpret_cast<PVOID>(printf), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &prot_buff)) { printf("Failed to enable page guard with VirtualProtect.\nGLE(get last error) code: %i", GetLastError()); return 0;}
    
    printf("%s", "Hooked.");
    printf("%s", "Hooked x2.");
    printf("%s", "Hooked x3");
    return 0;
}
