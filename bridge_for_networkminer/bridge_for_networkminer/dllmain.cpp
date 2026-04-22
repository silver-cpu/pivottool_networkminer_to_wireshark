// --- HEADERS AND LIBRARIES ---

// Standard Windows API for window management, threading, and memory
#include <windows.h>
// Microsoft UI Automation library to "read" the interface of other programs
#include <UIAutomation.h>
// Standard string library for handling wide-character (Unicode) text
#include <string>
// Vector container to store lists of objects in memory
#include <vector>
// Shell API for launching external programs like Wireshark or Command Prompt
#include <shellapi.h>
// Standard algorithms for searching, sorting, and data manipulation
#include <algorithm>
// Functions for wide-character classification (like checking if a character is a digit)
#include <cwctype>
// Regular Expressions library for pattern matching (IP addresses, MAC addresses)
#include <regex>
// Tool Help library for taking snapshots of running processes and threads
#include <tlhelp32.h>
// For the output and writing of temp files
#include <fstream>
// For exportation of data and getting the time and date
#include <ctime>

// Explicitly tells the linker to include the UI Automation library file
#pragma comment(lib, "UIAutomationCore.lib")

using namespace std;         // Uses the standard namespace to avoid typing 'std::' repeatedly


// --- CONSTANTS AND GLOBALS ---

// Unique ID for the 'Pivot' button control
#define ID_BTN_PIVOT 7001
// Unique ID for the 'Kill existing Wireshark' checkbox
#define ID_CHK_KILL_WS 7002
// Unique ID for the 'Use TShark' checkbox
#define ID_CHK_TSHARK 7003
// Unique ID for the 'EXPORT' button control
#define ID_BTN_EXPORT 7004

// Global handle to this DLL module instance in memory
HMODULE g_hDllModule = NULL;
// Window handles for: NetworkMiner (target), our HUD (monitor), and the text box (edit)
HWND hTargetWnd = NULL, hMonitorWnd = NULL, hEdit = NULL;

// Global string to store the most recently scraped data from the UI
wstring g_LatestData = L"";
// Global string to store the name of the .pcap file detected in NetworkMiner
wstring g_ActivePcapName = L"";

// Flags to signal: UI update needed, kill old Wireshark instances, or use CLI version
bool g_RequestUpdate = false;
bool g_KillExistingWS = false;
bool g_UseTShark = false;

// Structure to hold individual network fields for a specific selected row
struct PivotData {
    wstring frame, client, server, protocol, mac;
};

// A list (vector) that stores all data collected from currently selected items
vector<PivotData> g_PivotCollection;

// --- HELPER FUNCTIONS ---

// Function to find the folder path where this DLL is stored
wstring GetDllDirectory() {
    // Buffer to hold the file path (MAX_PATH is 260 characters)
    wchar_t path[MAX_PATH];
    // Retrieves the full path of the DLL using its module handle
    GetModuleFileNameW(g_hDllModule, path, MAX_PATH);
    // Convert the raw character array into a C++ string object
    wstring wsPath(path);
    // Find the last backslash to separate the directory from the filename
    size_t lastBackslash = wsPath.find_last_of(L"\\/");
    // If found, return everything before the slash; otherwise, return an empty string
    return (lastBackslash != wstring::npos) ? wsPath.substr(0, lastBackslash) : L"";
}

// Function to force-close any running Wireshark or TShark instances
void KillWiresharkProcesses() {
    if (g_UseTShark) {
        // EnumWindows is a Windows API function that "enumerates" (lists) every top-level window on the screen.
        // It takes a "Callback" function as its first argument—here, we use a C++ Lambda (the [] part).
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            // HWND (Window Handle) is the unique ID Windows uses to track a specific window.
            // We create two "wide-character" (Unicode) buffers to store the metadata we are about to pull from that handle.
            wchar_t className[256];  // Buffer for the internal Windows "Class Name" (type of window).
            wchar_t windowTitle[512]; // Buffer for the visible text shown in the window's title bar.
            // GetClassNameW retrieves the technical category of the window. 
            GetClassNameW(hwnd, className, 256);
            // wcscmp performs a strict, case-sensitive comparison of the class name.
            // "ConsoleWindowClass" is the hardcoded name Windows uses for the standard cmd.exe terminal.
            if (wcscmp(className, L"ConsoleWindowClass") == 0) {
                // If the window IS a command prompt, we now grab the text in its title bar.
                GetWindowTextW(hwnd, windowTitle, 512);
                // wcsstr searches the window title for our specific "tshark -r" substring.
                if (wcsstr(windowTitle, L"tshark -r") != nullptr) {
                    // If we found a match, we need to find the Process ID (PID) that "owns" this window.
                    DWORD pid;
                    // GetWindowThreadProcessId translates the Window Handle (HWND) into a System Process ID (PID).
                    GetWindowThreadProcessId(hwnd, &pid);
                    // OpenProcess requests a direct connection to the target cmd.exe process.
                    // PROCESS_TERMINATE is the specific security permission required to force-close a process.
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    // If the OS grants us permission (hProc is not null), we proceed to the kill.
                    if (hProc) {
                        // TerminateProcess sends the "Stop Immediately" signal to the process and all its threads.
                        TerminateProcess(hProc, 0);
                        // CloseHandle releases our connection to the process to prevent memory leaks in our own app.
                        CloseHandle(hProc);
                    }
                }
            }
            // Returning TRUE tells Windows to continue to the next window in its list.
            // If we returned FALSE, the search would stop immediately.
            return TRUE;
            }, 0); // The 0 is an optional parameter we aren't using (LPARAM).
    }
    // Create a snapshot of all currently running processes in Windows
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // If the snapshot fails, exit the function
    if (hSnap == INVALID_HANDLE_VALUE) return;

    // Structure to hold data about an individual process from the snapshot
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);

    // Retrieve information about the first process in the snapshot
    if (Process32FirstW(hSnap, &pe)) {
        do {
            // Perform a case-insensitive comparison to see if process matches Wireshark
            if (_wcsicmp(pe.szExeFile, L"wireshark.exe") == 0) {
                // Open the process with 'Terminate' permissions using its ID
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                // If successful, kill the process and close our handle to it
                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
            }
            // Move to the next process in the snapshot list
        } while (Process32NextW(hSnap, &pe));
    }
    // Clean up the snapshot handle
    CloseHandle(hSnap);
    // Brief pause to ensure Windows has finished closing the processes
    Sleep(300);
}

// --- SANITIZATION: Cleans UI strings to extract valid IP or MAC addresses ---
// str: The raw text from NetworkMiner; forceMac: If true, treats the string as a MAC address
wstring Sanitize(wstring str, bool forceMac = false) {
    // Variable to store the position of found text markers
    size_t pos;

    // Check if the string contains the prefix "IP: ". If so, cut everything before it.
    if ((pos = str.find(L"IP: ")) != wstring::npos) str = str.substr(pos + 4);

    // Check if the string contains the prefix "MAC: ". If so, cut everything before it.
    if ((pos = str.find(L"MAC: ")) != wstring::npos) str = str.substr(pos + 5);

    // Find the first space character; network addresses shouldn't have spaces in the middle.
    size_t firstSpace = str.find(L" ");
    // If a space exists, keep only the text before the space.
    if (firstSpace != wstring::npos) str = str.substr(0, firstSpace);

    // Trim leading whitespace: Remove any spaces at the very beginning of the string.
    str.erase(0, str.find_first_not_of(L" "));
    // Trim trailing whitespace: Remove any spaces at the very end of the string.
    str.erase(str.find_last_not_of(L" ") + 1);

    // Define a pattern for IPv4: 1-3 digits, followed by a dot, repeated 3 times, then 1-3 digits.
    wregex ip_regex(L"^(\\d{1,3}\\.){3}\\d{1,3}$");
    // Define a pattern for MAC: 5 pairs of hex characters with colons/dashes, then one more pair.
    wregex mac_regex(L"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");

    // If the cleaned string matches either the IP or MAC pattern, it's valid—return it.
    if (regex_match(str, ip_regex) || regex_match(str, mac_regex)) return str;

    // --- RAW MAC FIX: Handles MACs that are missing colons (e.g., 001122334455) ---
    // Create a copy of the string to manipulate
    wstring raw = str;
    // Remove any existing colons so we have a pure string of characters
    raw.erase(remove(raw.begin(), raw.end(), L':'), raw.end());

    // Check if we are forcing MAC mode, or if the string is 12 chars long and all Hex digits
    if (forceMac || (raw.length() == 12 && all_of(raw.begin(), raw.end(), ::iswxdigit))) {
        // String to hold the newly formatted MAC
        wstring fmt = L"";
        // Loop through the 12 characters, two at a time
        for (int i = 0; i < 12; i += 2) {
            // Add the two characters to our formatted string
            fmt += raw.substr(i, 2);
            // Add a colon between pairs, but not after the very last pair
            if (i < 10) fmt += L":";
        }
        return fmt;
    }
    // If it doesn't look like an IP or a MAC after all that, return an empty string
    return L"";
}

// --- LAUNCH SMART PIVOT: The engine that opens Wireshark with filters ---
void LaunchSmartPivot() {
    // If the user checked the "Kill" box, call our process terminator function
    if (g_KillExistingWS) KillWiresharkProcesses();

    // If no PCAP filename was found by the scraper, we can't pivot.
    if (g_ActivePcapName.empty()) {
        // Show an error popup to the user
        MessageBoxW(hMonitorWnd, L"No active PCAP detected!", L"Error", MB_ICONERROR);
        return;
    }

    // Combine the DLL's folder path with the PCAP name to get the full file location
    wstring fullPcapPath = GetDllDirectory() + L"\\" + g_ActivePcapName;
    // Initialize an empty string to build our Wireshark display filter
    wstring filter = L"";

    // Loop through every row of data currently stored in our collection (from the scraper)
    for (const auto& d : g_PivotCollection) {
        // Temporary string to hold the specific filter for this individual row
        wstring sub = L"";
        

        // If a frame number exists, create a filter for that specific packet
        if (!d.frame.empty()) sub = L"frame.number == " + d.frame;

        // Otherwise, if a MAC address exists...
        else if (!d.mac.empty()) {
            // Clean the MAC address using our Sanitize function
            wstring cm = Sanitize(d.mac, true);
            // If it's a valid MAC, create an Ethernet address filter
            if (!cm.empty()) sub = L"eth.addr == " + cm;
        }
        // If neither frame nor MAC were used, check if a Client (IP/Name) exists
        else if (!d.client.empty()) {
            // Clean the client string to see if it's a valid IP
            wstring cc = Sanitize(d.client);
            if (!cc.empty()) {
                // Regex to verify if the cleaned string is a standard IPv4 address
                wregex ip_check(L"^(\\d{1,3}\\.){3}\\d{1,3}$");
                if (regex_match(cc, ip_check)) {
                    // If it's an IP, create an IP address filter
                    sub = L"ip.addr == " + cc;
                    // If there is ALSO a server IP, add it to the filter with an 'AND' (&&)
                    if (!d.server.empty()) {
                        wstring cs = Sanitize(d.server);
                        if (!cs.empty()) sub += L" && ip.addr == " + cs;
                    }
                }
                // If it wasn't an IP, assume it's a MAC address name and filter by eth.addr
                else sub = L"eth.addr == " + cc;
            }
        }

        // If we generated a filter for this row (sub), append it to the master filter
        // If the master filter isn't empty, use '||' (OR) to combine them
        if (!sub.empty()) filter += (filter.empty() ? L"" : L" || ") + sub;
    }

    // Build the command line arguments: -r specifies the file to read
    wstring args = L"-r \"" + fullPcapPath + L"\"";
    // If we have a filter, add -Y (Display Filter) to the command
    if (!filter.empty()) args += L" -Y \"" + filter + L"\"";

    // Check if the user wants the CLI version (TShark)
    // NOTE MAKE SURE THAT YOU ADD TO THE SYSTEM ENVIRONMENT VARIABLES:
    //      ADD TO THE "PATH" THE FOLDER LOCATION OF THE Wireshark installation (Example:  C:\Program Files\Wireshark\   )
    if (g_UseTShark) {
        // 1. Build the full command string for tshark
        wstring fullCommand = L"tshark " + args;
        

        // 2. Build the CMD arguments: 
        //    'title [text]' - Sets the window title
        //    'echo [command]' prints the text
        //    ' & ' joins the next command
        //    '[command]' actually runs tshark
        //    /k keeps it open
        wstring cmdArgs = L"/k title " + fullCommand + L" & echo Running: " + fullCommand + L" & " + fullCommand;

        // 3. Launch the command prompt
        ShellExecuteW(NULL, L"open", L"cmd.exe", cmdArgs.c_str(), NULL, SW_SHOWNORMAL);
    }
    else {
        // Otherwise, launch the standard Wireshark GUI with our arguments
        ShellExecuteW(NULL, L"open", L"wireshark.exe", args.c_str(), NULL, SW_SHOWNORMAL);
    }
}

wstring tempOutput(wstring pull) {
    wchar_t buf[20];
    time_t now = time(nullptr);
    tm t;
    localtime_s(&t, &now);
    // Format: YYYY-MM-DD_HH-MM-SS
    wcsftime(buf, 20, L"%Y-%m-%d_%H-%M-%S", &t);
    wofstream(GetDllDirectory() + L"\\lastexamined.txt") << buf << endl << pull;
    return pull;
}
//copies over from the tempOutput when the desired content is on the screen and the button EXPORT is clicked
void Export() {
    CopyFileW(L"lastexamined.txt", L"EXPORTED.txt", 0);
    MessageBoxW(hMonitorWnd, L"Exported to current directory EXPORTED.txt!", L"Exported", 0);
}

// --- DATA SCRAPER WORKER: The background thread that "reads" NetworkMiner ---
DWORD WINAPI DataScraperWorker(LPVOID lpParam) {
    // Initialize COM (Component Object Model) for this thread
    // COINIT_MULTITHREADED allows this thread to work independently
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    // Pointer to the master UI Automation object
    IUIAutomation* pAutomation = NULL;
    // Create the UI Automation instance (The "engine" that interacts with other apps)
    CoCreateInstance(CLSID_CUIAutomation, NULL, CLSCTX_INPROC_SERVER, IID_IUIAutomation, (void**)&pAutomation);
    wstring currentOutput = L"";
    // Infinite loop to keep scraping as long as the tool is running
    while (true) {
        // Check if we have a valid handle to the NetworkMiner window
        if (hTargetWnd && IsWindow(hTargetWnd)) {
            // Pointer to the root element (The NetworkMiner Window itself)
            IUIAutomationElement* pRoot = NULL;
            // Get the UI Automation object for the NetworkMiner window handle
            pAutomation->ElementFromHandle(hTargetWnd, &pRoot);

            if (pRoot) {
                // --- PCAP LOOKUP: Finding the filename ---
                IUIAutomationCondition* pTrue;
                // Create a 'True' condition (Matches everything) to find all child elements
                pAutomation->CreateTrueCondition(&pTrue);

                IUIAutomationElementArray* pAll;
                // Search every sub-element inside NetworkMiner for the filename
                pRoot->FindAll(TreeScope_Descendants, pTrue, &pAll);

                if (pAll) {
                    int len; pAll->get_Length(&len);
                    // Loop through every single UI element found
                    for (int i = 0; i < len; i++) {
                        IUIAutomationElement* pEl;
                        pAll->GetElement(i, &pEl);
                        BSTR name;
                        // Get the text/name of the current UI element
                        pEl->get_CurrentName(&name);

                        if (name) {
                            wstring nStr = name;
                            // If the text contains ".pcap", we found our active file!
                            if (nStr.find(L".pcap") != wstring::npos) {
                                g_ActivePcapName = nStr;
                                SysFreeString(name); pEl->Release(); break;
                            }
                            // Free memory for strings that didn't match
                            SysFreeString(name);
                        }
                        pEl->Release();
                    }
                    pAll->Release();
                }

                // Initialize the text that will appear in our HUD (Forensic Inspector window)
                currentOutput = L"--- FORENSIC INSPECTOR ACTIVE ---\r\n";

                // If we found a PCAP file, show the full path as a reference in the HUD
                if (!g_ActivePcapName.empty()) {
                    currentOutput += L"REF: " + GetDllDirectory() + L"\\" + g_ActivePcapName + L"\r\n";
                }

                // Temporary list to hold data from the current scan cycle
                vector<PivotData> tempPivot;

                // --- HEADER DETECTION LOGIC ---
                // Pointer for a search condition
                IUIAutomationCondition* pHdrCond;
                VARIANT vH; vH.vt = VT_I4;
                // Set search criteria to look specifically for "Header Items" (column titles)
                vH.lVal = UIA_HeaderItemControlTypeId;

                // Tell the automation engine to find elements matching the "Header" type
                pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, vH, &pHdrCond);

                IUIAutomationElementArray* pHdrs;
                // Scan the window for all column headers (e.g., "Source", "Destination", "MAC")
                pRoot->FindAll(TreeScope_Descendants, pHdrCond, &pHdrs);

                // List to store the text of the headers we find
                vector<wstring> headers;
                if (pHdrs) {
                    int hl; pHdrs->get_Length(&hl);
                    for (int i = 0; i < hl; i++) {
                        IUIAutomationElement* ph; pHdrs->GetElement(i, &ph);
                        BSTR n; ph->get_CurrentName(&n);
                        // Store header name (like "Source"); use "Field" as a fallback if empty
                        headers.push_back(n ? n : L"Field");
                        // Clean up memory for the header string and element
                        if (n) SysFreeString(n); ph->Release();
                    }
                    pHdrs->Release();
                }

                // --- SELECTION DETECTION LOGIC ---
                IUIAutomationCondition* pSelCond;
                VARIANT vs; vs.vt = VT_BOOL;
                // Set search criteria to find items where "IsSelected" is True
                vs.boolVal = VARIANT_TRUE;

                // Create a condition to find only the rows currently highlighted by the user
                pAutomation->CreatePropertyCondition(UIA_SelectionItemIsSelectedPropertyId, vs, &pSelCond);

                IUIAutomationElementArray* pItems;
                // Execute the search for all selected rows
                pRoot->FindAll(TreeScope_Descendants, pSelCond, &pItems);

                if (pItems) {
                    int itemCount; pItems->get_Length(&itemCount);
                    // Index used for labeling entries in our HUD [ENTRY 1], [ENTRY 2], etc.
                    int vIdx = 1;
                    for (int i = 0; i < itemCount; i++) {
                        IUIAutomationElement* pItem; pItems->GetElement(i, &pItem);
                        BSTR name; pItem->get_CurrentName(&name);

                        // Convert the BSTR to a standard C++ wide string
                        wstring nStr = name ? name : L"";

                        // Prevent pcap files as being read into the Forensic Window
                        if (nStr.find(L".pcap") != wstring::npos) {
                            if (name) SysFreeString(name); pItem->Release(); continue;
                        }
                        
                        // Buffer for the row's text and a structure to store the network data
                        wstring entryData = L""; PivotData pd; bool hasData = false;

                        // Check the main row text (nStr) for an IP address immediately
                        wstring ipCheck = Sanitize(nStr);
                        if (!ipCheck.empty()) { pd.client = ipCheck; hasData = true; }

                        // --- CELL SCRAPING ---
                        IUIAutomationElementArray* pCells; IUIAutomationCondition* pTr;
                        // Create a "True" condition to find all sub-elements (cells) of the row
                        pAutomation->CreateTrueCondition(&pTr);
                        // Search for direct children of the selected row (these are the table cells)
                        pItem->FindAll(TreeScope_Children, pTr, &pCells);

                        if (pCells) {
                            int cl; pCells->get_Length(&cl);
                            for (int c = 0; c < cl; c++) {
                                IUIAutomationElement* pCell; pCells->GetElement(c, &pCell);
                                BSTR val; pCell->get_CurrentName(&val);
                                // Determine the column name based on our previously scraped 'headers' list
                                wstring label = (c < headers.size()) ? headers[c] : L"Data";

                                if (val && SysStringLen(val) > 0) {
                                    hasData = true;
                                    // Build the text display for our HUD: "Header: Value"
                                    entryData += label + L": " + val + L"\r\n";

                                    // Logic to map the specific cell value to our PivotData structure
                                    if (label.find(L"Source") != wstring::npos || label.find(L"Client") != wstring::npos) pd.client = val;
                                    if (label.find(L"Destination") != wstring::npos || label.find(L"Server") != wstring::npos) pd.server = val;
                                    if (label.find(L"Frame") != wstring::npos) pd.frame = val;
                                    if (label.find(L"MAC") != wstring::npos) pd.mac = val;
                                }
                                if (val) SysFreeString(val); pCell->Release();
                            }
                            pCells->Release();
                        }

                        // If the row contained useful data, add it to our global collection for pivoting
                        if (hasData) {
                            tempPivot.push_back(pd);
                            currentOutput += L"\r\n[ENTRY " + to_wstring(vIdx++) + L"]\r\n" + entryData;
                            tempOutput(currentOutput);
                        }
                        if (name) SysFreeString(name); pItem->Release();
                    }
                    pItems->Release();
                }
                
                // If the data we just scraped is different from the last scan, trigger a UI update
                if (currentOutput != g_LatestData) {
                    g_LatestData = currentOutput;
                    g_PivotCollection = tempPivot;
                    g_RequestUpdate = true;
                    
                }
                pRoot->Release();
            }
        }
        // Wait 500ms before scanning NetworkMiner again to save CPU
        Sleep(500);
    }
    
    return 0;
}




// --- HUD WINDOW PROCEDURE: Handles clicks and interactions with our tool window ---
LRESULT CALLBACK HUDProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_COMMAND) {
        // If the 'PIVOT' button is clicked
        if (LOWORD(wp) == ID_BTN_PIVOT) LaunchSmartPivot();
        // If the 'EXPORT' button is clicked
        if (LOWORD(wp) == ID_BTN_EXPORT) Export();
        // If the 'Kill' checkbox is toggled, update our global boolean
        if (LOWORD(wp) == ID_CHK_KILL_WS) g_KillExistingWS = (SendMessage((HWND)lp, BM_GETCHECK, 0, 0) == BST_CHECKED);
        // If the 'TShark' checkbox is toggled, update our global boolean
        if (LOWORD(wp) == ID_CHK_TSHARK) g_UseTShark = (SendMessage((HWND)lp, BM_GETCHECK, 0, 0) == BST_CHECKED);
        
        return 0;
    }
    // Allow the window to be dragged by clicking anywhere (not just the title bar)
    if (msg == WM_NCHITTEST) return (DefWindowProcW(hWnd, msg, wp, lp) == HTCLIENT) ? HTCAPTION : DefWindowProcW(hWnd, msg, wp, lp);
    return DefWindowProcW(hWnd, msg, wp, lp);
}

// --- UI THREAD: Creates the visual window and buttons ---
DWORD WINAPI UIThread(LPVOID lpParam) {
    // Find the NetworkMiner window on the desktop
    while (!hTargetWnd) { hTargetWnd = FindWindowW(NULL, L"NetworkMiner 3.1"); Sleep(500); }
    


    // Register the window class for our HUD
    WNDCLASSW wc = { 0 }; wc.lpfnWndProc = HUDProc; wc.lpszClassName = L"ForensicHUD";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    // Create the main HUD window (Topmost, non-resizable by default)
    hMonitorWnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"ForensicHUD", L"FORENSIC INSPECTOR", WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME, 100, 100, 480, 580, NULL, NULL, NULL, NULL);

    // Create the PIVOT button, Checkboxes, and the Multi-line Edit (Text) box
    CreateWindowExW(0, L"BUTTON", L"PIVOT", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 360, 10, 80, 35, hMonitorWnd, (HMENU)ID_BTN_PIVOT, NULL, NULL);
    CreateWindowExW(0, L"BUTTON", L"EXPORT", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 260, 10, 80, 35, hMonitorWnd, (HMENU)ID_BTN_EXPORT, NULL, NULL);
    CreateWindowExW(0, L"BUTTON", L"Kill existing Wireshark/Tshark", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 15, 10, 240, 20, hMonitorWnd, (HMENU)ID_CHK_KILL_WS, NULL, NULL);
    CreateWindowExW(0, L"BUTTON", L"Use tshark (CLI)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 15, 30, 200, 20, hMonitorWnd, (HMENU)ID_CHK_TSHARK, NULL, NULL);
    hEdit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 10, 60, 445, 470, hMonitorWnd, NULL, NULL, NULL);

    // Set a cleaner font for the text display
    SendMessage(hEdit, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

    // Launch the Scraper thread
    CreateThread(NULL, 0, DataScraperWorker, NULL, 0, NULL);

    // This loop runs as long as the HUD window exists; if the window is closed, the thread exits
    while (IsWindow(hMonitorWnd)) {
        // Check if the background scraper thread has flagged that new forensic data is ready
        if (g_RequestUpdate) {
            // Push the latest scraped string into the multi-line edit box for the user to see
            SetWindowTextW(hEdit, g_LatestData.c_str());
            // Reset the flag so we don't waste CPU re-setting the same text repeatedly
            g_RequestUpdate = false;
        }
        // Standard Windows Message Queue handling
        MSG m;
        // PeekMessage checks for clicks, drags, or close events without "freezing" the loop
        if (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m); // Translates virtual-key messages into character messages
            DispatchMessageW(&m); // Sends the message to our HUDProc for processing
        }
        // Pause for 10 milliseconds to prevent this thread from consuming 100% of a CPU core
        Sleep(10);
    }
    return 0;
}

// --- DLL ENTRY POINT ---
BOOL APIENTRY DllMain(HMODULE hMod, DWORD r, LPVOID l) {
    // When the DLL is loaded into memory (Process Attach)
    if (r == DLL_PROCESS_ATTACH) {
        g_hDllModule = hMod;
        // Kick off the UI thread immediately
        CreateThread(0, 0, UIThread, 0, 0, 0);
    }
    return 1;
}
