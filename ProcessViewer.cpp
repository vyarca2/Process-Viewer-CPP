#include <wx/listctrl.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>
#include <sstream>
#include <cstdint> 
#include <wx/wx.h>
#include <wx/dialog.h> 
#include <wx/sizer.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>

#else
#include <dirent.h>
#include<proc/readproc.h>
#include <unistd.h>
#include <cstring>
#include <cwchar> 
#include <locale> 
#include <codecvt> 
#endif

#ifndef _WIN32
typedef uint32_t DWORD;
#endif

std::wstring ConvertToWideString(const char* str) 
{
#ifdef _WIN32

    int numChars = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (numChars == 0) 
    {
        return L"";
    }

    std::wstring wideStr(numChars, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &wideStr[0], numChars);
    return wideStr;

#else

    std::wstringstream wss;
    wss << str;
    return wss.str();

#endif
}

std::vector<std::wstring> GetRunningProcesses() 
{
    std::vector<std::wstring> processes;

#ifdef _WIN32

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) 
    {
        std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
        return processes;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &processEntry)) 
    {
        do 
        {
            char narrowStr[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, processEntry.szExeFile, -1, narrowStr, MAX_PATH, nullptr, nullptr);
            std::wstring processName = ConvertToWideString(narrowStr);
            processes.push_back(processName);
        } 
        while (Process32Next(hSnapshot, &processEntry));
    }

    else 
    {
        std::cerr << "Failed to retrieve process information. Error code: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);

#else

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    PROCTAB* pt = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);

    if (!pt) 
    {
        std::cerr << "Failed to open the process table." << std::endl;
        return processes;
    }

    proc_t procInfo;
    memset(&procInfo,0,sizeof(procInfo));

    while (readproc(pt, &procInfo) != nullptr) 
    {
        std::wstring processName = converter.from_bytes(procInfo.cmd);
        std::wcout<<processName<<std::endl;
        processes.push_back(processName);
    }

    closeproc(pt);

#endif

    return processes;
}

#ifdef _WIN32

std::vector<DWORD> GetChildProcesses(DWORD parentProcessID) 
{
    std::vector<DWORD> childProcesses;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) 
    {
        std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
        return childProcesses;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &processEntry)) 
    {
        do 
        {
            if (processEntry.th32ParentProcessID == parentProcessID) 
            {
                childProcesses.push_back(processEntry.th32ProcessID);
            }
        } 
        while (Process32Next(hSnapshot, &processEntry));
    }
    else 
    {
        std::cerr << "Failed to retrieve process information. Error code: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);
    return childProcesses;
}

#else

std::vector<unsigned int> GetChildProcesses(unsigned int parentProcessID) 
{
    std::vector<unsigned int> childProcesses;
    DIR* dir = opendir("/proc");

    if (dir != nullptr) 
    {
        dirent* entry;

        while ((entry = readdir(dir)) != nullptr) 
        {
            if (entry->d_type == DT_DIR) 
            {
                char* endptr;
                long pid = strtol(entry->d_name, &endptr, 10);
                
                if (*endptr == '\0' && pid != parentProcessID) 
                {
                    char filename[256];
                    snprintf(filename, sizeof(filename), "/proc/%ld/stat", pid);
                    FILE* statFile = fopen(filename, "r");
                    
                    if (statFile) 
                    {
                        int ppid; 
                        fscanf(statFile, "%*d %*s %*c %d", &ppid);
                        fclose(statFile);
                        
                        if (ppid == parentProcessID) 
                        {
                            childProcesses.push_back(pid);
                        }
                    }
                }
            }
        }
        closedir(dir);
    }
    else 
    {
        std::cerr << "Failed to open /proc directory." << std::endl;
    }

    return childProcesses;
}

unsigned int GetProcessIDByProcessName(const std::wstring& processName) 
{
    std::vector<std::wstring> processNames = GetRunningProcesses();

    for (const auto& name : processNames) 
    {
        if (name.find(processName) != std::wstring::npos) 
        {
            unsigned int pid = std::stoi(name);
            return pid;
        }
    }
    return 0;
}
#endif

class ProcessViewerFrame : public wxFrame 
{
public:
    ProcessViewerFrame() : wxFrame(nullptr, wxID_ANY, "Running Processes Viewer", wxDefaultPosition, wxSize(800, 600)) 
    {
        wxPanel* panel = new wxPanel(this, wxID_ANY);

        processListCtrl = new wxListCtrl(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_SINGLE_SEL);
        processListCtrl->InsertColumn(0, "PID", wxLIST_FORMAT_LEFT, 100);
        processListCtrl->InsertColumn(1, "Process Name", wxLIST_FORMAT_LEFT, 200);
        processListCtrl->InsertColumn(2, "Physical Memory (KB)", wxLIST_FORMAT_LEFT, 150);
        processListCtrl->InsertColumn(3, "Virtual Memory (KB)", wxLIST_FORMAT_LEFT, 150);

        childListCtrl = new wxListCtrl(panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT);
        childListCtrl->InsertColumn(0, "Child Process Name", wxLIST_FORMAT_LEFT, 200);

        wxButton* killButton = new wxButton(panel, wxID_ANY, "Kill Process");
        wxButton* listChildButton = new wxButton(panel, wxID_ANY, "List Child Processes");

        wxBoxSizer* processSizer = new wxBoxSizer(wxVERTICAL);
        processSizer->Add(processListCtrl, 1, wxEXPAND | wxALL, 10);
        processSizer->Add(killButton, 0, wxALIGN_RIGHT | wxALL, 10);
        processSizer->Add(listChildButton, 0, wxALIGN_RIGHT | wxALL, 10);

        wxBoxSizer* childSizer = new wxBoxSizer(wxVERTICAL);
        childSizer->Add(childListCtrl, 1, wxEXPAND | wxALL, 10);

        //searchInput = new wxTextCtrl(panel, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
        wxButton* searchButton = new wxButton(panel, wxID_ANY, "Search");

        wxBoxSizer* searchSizer = new wxBoxSizer(wxHORIZONTAL);
        searchSizer->Add(searchInput, 1, wxEXPAND | wxALL, 10);
        searchSizer->Add(searchButton, 0, wxALIGN_RIGHT | wxALL, 10);

        // Combine all sizers
        wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
        mainSizer->Add(processSizer, 1, wxEXPAND | wxALL, 10);
        mainSizer->Add(childSizer, 1, wxEXPAND | wxALL, 10);
        mainSizer->Add(searchSizer, 0, wxEXPAND | wxALL, 10);

        panel->SetSizer(mainSizer);
        this->Layout();

        LoadProcesses();

        // Bind the search button event
        searchButton->Bind(wxEVT_BUTTON, &ProcessViewerFrame::OnSearchButtonClicked, this);

        killButton->Bind(wxEVT_BUTTON, &ProcessViewerFrame::OnKillProcess, this);
        listChildButton->Bind(wxEVT_BUTTON, &ProcessViewerFrame::OnListChildProcesses, this);
        processListCtrl->Bind(wxEVT_LIST_ITEM_SELECTED, &ProcessViewerFrame::OnProcessSelected, this);
    }

private:
    DWORD selectedProcessID; 
    wxTextCtrl* searchInput;
    wxButton* searchButton;
    std::vector<std::pair<std::wstring, DWORD>> GetRunningProcessesWithPID() 
    {
        std::vector<std::pair<std::wstring, DWORD>> processes;

#ifdef _WIN32
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hSnapshot != INVALID_HANDLE_VALUE) 
        {
            PROCESSENTRY32 processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &processEntry)) 
            {
                do 
                {
                    char narrowStr[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, processEntry.szExeFile, -1, narrowStr, MAX_PATH, nullptr, nullptr);
                    std::wstring processName = ConvertToWideString(narrowStr);
                    processes.push_back({ processName, processEntry.th32ProcessID });
                } 
                while (Process32Next(hSnapshot, &processEntry));
            }
            else 
            {
                std::cerr << "Failed to retrieve process information. Error code: " << GetLastError() << std::endl;
            }

            CloseHandle(hSnapshot);
        }
        else 
        {
            std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
        }
        
#else

        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        PROCTAB* pt = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);

        if (!pt) 
        {
            std::cerr << "Failed to open the process table." << std::endl;
            return processes;
        }

        proc_t procInfo;
        memset(&procInfo,0,sizeof(procInfo));

        while (readproc(pt, &procInfo) != nullptr) 
        {
            std::wstring processName = converter.from_bytes(procInfo.cmd);
            DWORD pid = static_cast<DWORD>(procInfo.tid);
            processes.push_back({processName,pid});
        }

        closeproc(pt);

#endif

        return processes;
    }

    void LoadProcesses(const wxString& searchFilter = wxEmptyString)
    {
        std::vector<std::pair<std::wstring, DWORD>> processesWithPID = GetRunningProcessesWithPID();
        int pidIndex = 0; 
        int nameIndex = 1; 
        int physicalMemoryIndex = 2; 
        int virtualMemoryIndex = 3; 
        
        for (const auto& processPair : processesWithPID) 
        {
            const std::wstring& processName = processPair.first;
            DWORD pid = processPair.second;
            std::wstring pidStr = std::to_wstring(pid);

            if (searchFilter.empty() || processName.find(searchFilter) != std::wstring::npos) {
                // Get memory information for the process
                auto memoryInfo = GetProcessMemoryInfoByPID(pid);
                int virtualMemory = memoryInfo.first;
                int physicalMemory = memoryInfo.second;

                long index = processListCtrl->InsertItem(processListCtrl->GetItemCount(), pidStr);
                processListCtrl->SetItem(index, nameIndex, wxString(processName.c_str()));
                processListCtrl->SetItem(index, physicalMemoryIndex, wxString::Format("%d", physicalMemory));
                processListCtrl->SetItem(index, virtualMemoryIndex, wxString::Format("%d", virtualMemory));
            }
        }
    }

    std::pair<int, int> GetProcessMemoryInfoByPID(DWORD pid) 
    {
        int physicalMemory = 0;
        int virtualMemory = 0;

#ifdef _WIN32

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        if (hProcess != nullptr) 
        {
            PROCESS_MEMORY_COUNTERS_EX memoryInfo;

            if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&memoryInfo, sizeof(memoryInfo))) 
            {
                virtualMemory = static_cast<int>(memoryInfo.PrivateUsage / 1024);
                physicalMemory = static_cast<int>(memoryInfo.WorkingSetSize / 1024);
            }

            CloseHandle(hProcess);
        }
#else
        std::ifstream statFile("/proc/" + std::to_string(pid) + "/statm");

        if (statFile.is_open()) 
        {
            statFile >> virtualMemory >> physicalMemory;
            statFile.close();

            long pageSize = sysconf(_SC_PAGESIZE) / 1024;
            virtualMemory *= pageSize;
            physicalMemory *= pageSize;
        }
#endif
        return { virtualMemory, physicalMemory };
    }

    void ListChildProcesses() 
    {
        childListCtrl->DeleteAllItems();
        std::vector<DWORD> childProcesses = GetChildProcesses(selectedProcessID);

        for (DWORD pid : childProcesses) 
        {
            const std::wstring& processName = GetProcessNameByPID(pid);
            long index = childListCtrl->InsertItem(childListCtrl->GetItemCount(), wxString(processName.c_str()));
        }
    }

    std::wstring GetProcessNameByPID(DWORD pid) 
    {
        std::vector<std::pair<std::wstring, DWORD>> processesWithPID = GetRunningProcessesWithPID();

        for (const auto& processPair : processesWithPID) 
        {
            if (processPair.second == pid) 
            {
                return processPair.first;
            }
        }
        return L"";
    }

    void OnProcessSelected(wxListEvent& event) 
    {
        long selectedItemIndex = processListCtrl->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);

        if (selectedItemIndex != -1) 
        {
            wxString pidStr = processListCtrl->GetItemText(selectedItemIndex, 0);
            pidStr.ToULong(reinterpret_cast<unsigned long*>(&selectedProcessID));
        }
    }
    void OnSearchButtonClicked(wxCommandEvent& event) {
        wxTextEntryDialog dialog(this, "Enter the process name to search:", "Search Process");
        if (dialog.ShowModal() == wxID_OK) {
            wxString searchText = dialog.GetValue();
            searchText.Trim(true).Trim(false); // Trim leading and trailing spaces
            if (searchText.IsEmpty()) {
                // If the search text is empty, show all processes again
                LoadProcesses();
            }
            else {
                // Convert the wxString to std::wstring for comparison
                std::wstring searchWText = searchText.ToStdWstring();

                // Find the index of the process with the matching name
                long index = -1;
                for (int i = 0; i < processListCtrl->GetItemCount(); i++) {
                    wxString processName = processListCtrl->GetItemText(i, 1);
                    if (processName.find(searchText) != wxNOT_FOUND) {
                        index = i;
                        break;
                    }
                }

                // If a matching process is found, select (highlight) it in the list
                if (index != -1) {
                    processListCtrl->SetItemState(index, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                    processListCtrl->EnsureVisible(index); // Scroll to make the item visible
                }
                else {
                    // If no matching process is found, show a message
                    wxMessageBox("No process with the given name found.", "Process Not Found", wxOK | wxICON_INFORMATION, this);
                }
            }
        }
    }
    void OnListChildProcesses(wxCommandEvent& event) 
    {
        ListChildProcesses();
    }

    void OnKillProcess(wxCommandEvent& event) 
    {
        if (selectedProcessID != 0) 
        {
#ifdef _WIN32

            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, selectedProcessID);

            if (hProcess != nullptr) 
            {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                LoadProcesses(); 
                ListChildProcesses(); 
            }
#else
            if (kill(selectedProcessID, SIGTERM) == 0) 
            {
                LoadProcesses(); 
                ListChildProcesses(); 
            }
#endif
        }
    }

    wxListCtrl* processListCtrl;
    wxListCtrl* childListCtrl;

    wxDECLARE_EVENT_TABLE();
};

wxBEGIN_EVENT_TABLE(ProcessViewerFrame, wxFrame)
EVT_LIST_ITEM_SELECTED(wxID_ANY, ProcessViewerFrame::OnProcessSelected)
EVT_BUTTON(wxID_ANY, ProcessViewerFrame::OnKillProcess)
EVT_BUTTON(wxID_ANY, ProcessViewerFrame::OnListChildProcesses)
wxEND_EVENT_TABLE()

class ProcessViewerApp : public wxApp 
{
public:
    bool OnInit() override 
    {
        ProcessViewerFrame* frame = new ProcessViewerFrame();
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(ProcessViewerApp);
