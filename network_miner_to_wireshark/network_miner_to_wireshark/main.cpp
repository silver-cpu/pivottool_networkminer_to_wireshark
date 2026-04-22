#include <windows.h>         // Includes the core Windows API functions (processes, memory, threads)
#include <iostream>          // Includes input/output stream for printing to the console
#include <string>            // Includes the string class to handle file paths easily

using namespace std;         // Uses the standard namespace to avoid typing 'std::' repeatedly

int main() {
    // --- CONFIGURATION ---
    // Stores the relative path to your custom Bridge DLL that contains the scraper/pivot logic
    string dllPath = ".\\bridge_for_networkminer.dll";
    // Stores the relative path to the NetworkMiner executable file
    string exePath = "..\\NetworkMiner.exe";
    // ---------------------

    // Initializes a STARTUPINFO structure which defines how the new window should look (default settings)
    STARTUPINFOA si = { sizeof(si) };
    // Initializes a PROCESS_INFORMATION structure to receive identifying handles for the new process
    PROCESS_INFORMATION pi;

    // Prints a status message to the console window
    cout << "Launching NetworkMiner..." << endl;

    // Attempts to start NetworkMiner.exe using the path provided, creating a new process
    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // If the file path is wrong or permissions are denied, print an error
        cout << "Error: Could not launch NetworkMiner. Check your path." << endl;
        // Keeps the console window open so you can read the error before it disappears
        system("pause");
        // Exit the program with an error code
        return 1;
    }

    // Pauses the injector for 2 seconds to give NetworkMiner time to load its window and memory
    Sleep(2000);

    // Allocates a small block of empty memory inside NetworkMiner's process space to hold our DLL path string
    void* loc = VirtualAllocEx(pi.hProcess, 0, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // Physically copies the characters of ".\\bridge_for_networkminer.dll" into that newly allocated memory
    WriteProcessMemory(pi.hProcess, loc, dllPath.c_str(), dllPath.length() + 1, 0);

    // Forces NetworkMiner to start a new thread that calls 'LoadLibraryA' using our DLL path as the target
    HANDLE hThread = CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

    // Checks if the remote thread was successfully created
    if (hThread) {
        // Confirms that your C++ DLL is now running inside the NetworkMiner process
        cout << "Injection Successful! Keeping console open for bridge..." << endl << "You are free to close this CMD window:" << endl;
        // Closes the handle to the remote thread (does not stop the thread, just cleans up our handle)
        CloseHandle(hThread);
    }
    else {
        // If the thread failed to start, print the specific Windows error code for troubleshooting
        cout << "Injection Failed. Error: " << GetLastError() << endl;
    }

    // Closes the handle to the NetworkMiner process object to avoid memory leaks in the injector
    CloseHandle(pi.hProcess);
    // Closes the handle to the main thread of NetworkMiner
    CloseHandle(pi.hThread);
    // Keeps the injector console alive so the user can verify the result
    system("pause");
    // Exit the program successfully
    return 0;
}
