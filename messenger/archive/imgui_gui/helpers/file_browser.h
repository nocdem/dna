#ifndef FILE_BROWSER_H
#define FILE_BROWSER_H

#include <string>
#include <vector>

// Forward declaration
class AsyncTask;

namespace FileBrowser {
    
    enum FileType {
        FILE_TYPE_ANY,
        FILE_TYPE_IMAGES,
        FILE_TYPE_WALLETS
    };
    
    struct FileFilter {
        const char* name;
        const char* extensions;
    };
    
    // Open file browser dialog and return selected file path
    // Returns empty string if cancelled or error
    std::string openFileDialog(const std::string& title, FileType type = FILE_TYPE_ANY);
    
    // Open file browser with custom filters
    std::string openFileDialog(const std::string& title, const FileFilter* filters, int filter_count);
    
    // Save file dialog
    std::string saveFileDialog(const std::string& title, const std::string& default_name = "", FileType type = FILE_TYPE_ANY);
    
    // Get last error message
    const std::string& getLastError();
    
    // Multiple file selection
    std::vector<std::string> openMultipleFileDialog(const std::string& title, FileType type = FILE_TYPE_ANY);
    std::vector<std::string> openMultipleFileDialog(const std::string& title, const FileFilter* filters, int filter_count);
    
    // Async versions (requires AsyncTask from async_helpers.h)
    void openFileDialogAsync(AsyncTask* task, const std::string& title, FileType type = FILE_TYPE_ANY);
    void openMultipleFileDialogAsync(AsyncTask* task, const std::string& title, FileType type = FILE_TYPE_ANY);
    std::string getAsyncResult(); // Get result after async completion
    std::vector<std::string> getAsyncMultipleResults(); // Get multiple results after async completion
    
} // namespace FileBrowser

#endif // FILE_BROWSER_H