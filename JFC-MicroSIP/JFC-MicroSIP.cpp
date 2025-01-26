#include <windows.h>
#include <fstream>
#include <string>

void runApp(const std::string& appPath) {
    // Determine if the app is a console or GUI app by checking its file extension
    // This assumes you are launching an exe that could be either a GUI or console app
    std::string extension = appPath.substr(appPath.find_last_of('.') + 1);

    // If it's a console app, show the window, otherwise hide it
    int showWindowFlag = (extension == "exe") ? SW_SHOWNORMAL : SW_HIDE;

    // Execute the application
    ShellExecuteA(NULL, "open", appPath.c_str(), NULL, NULL, showWindowFlag);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Get the directory of the executable
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);  // Get path of current executable
    std::string exeDir = std::string(buffer);
    size_t lastSlash = exeDir.find_last_of("\\/");
    exeDir = exeDir.substr(0, lastSlash);  // Extract directory path from the full path

    // Define the path of the JFC_CONFIG_DONE file
    std::string configFilePath = exeDir + "\\JFC_CONFIG_DONE";
    std::string microsipPath = exeDir + "\\microsip.exe";
    std::string configPath = exeDir + "\\jfc_configure.exe";

    // Check if JFC_CONFIG_DONE exists
    std::ifstream configFile(configFilePath);
    if (configFile) {
        // If the file exists, run microsip.exe
        runApp(microsipPath);
    }
    else {
        // If the file does not exist, run jfc_configure.exe
        runApp(configPath);
    }

    return 0;  // Exit the Windows application
}
