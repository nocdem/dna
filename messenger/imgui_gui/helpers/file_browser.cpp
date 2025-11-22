#include "file_browser.h"
#include "async_helpers.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <nfd.h>
#endif

namespace FileBrowser {

static std::string last_error;
static std::string async_result;

const FileFilter IMAGE_FILTERS[] = {
    {"Image Files", "png,jpg,jpeg,bmp,gif"}
};

const FileFilter WALLET_FILTERS[] = {
    {"Wallet Files", "dat,wallet,json"},
    {"All Files", "*"}
};

const std::string& getLastError() {
    return last_error;
}

std::string openFileDialog(const std::string& title, FileType type) {
    switch (type) {
        case FILE_TYPE_IMAGES:
            return openFileDialog(title, IMAGE_FILTERS, 1);
        case FILE_TYPE_WALLETS:
            return openFileDialog(title, WALLET_FILTERS, 2);
        default:
            return openFileDialog(title, nullptr, 0);
    }
}

std::string openFileDialog(const std::string& title, const FileFilter* filters, int filter_count) {
    last_error.clear();
    
#ifdef _WIN32
    // Windows: Use NFD
    nfdchar_t *outPath = nullptr;
    nfdresult_t result;
    
    if (filters && filter_count > 0) {
        // Convert filters to NFD format
        nfdfilteritem_t* nfd_filters = new nfdfilteritem_t[filter_count];
        for (int i = 0; i < filter_count; i++) {
            nfd_filters[i].name = filters[i].name;
            nfd_filters[i].spec = filters[i].extensions;
        }
        result = NFD_OpenDialog(&outPath, nfd_filters, filter_count, nullptr);
        delete[] nfd_filters;
    } else {
        result = NFD_OpenDialog(&outPath, nullptr, 0, nullptr);
    }
    
    if (result == NFD_OKAY) {
        std::string path(outPath);
        NFD_FreePath(outPath);
        return path;
    } else if (result == NFD_ERROR) {
        last_error = "File dialog error: ";
        last_error += NFD_GetError();
    }
    // NFD_CANCEL is not an error, just return empty string
    
#else
    // Linux: Detect desktop environment and use appropriate dialog
    const char *desktop_env = getenv("XDG_CURRENT_DESKTOP");
    const char *kde_session = getenv("KDE_SESSION_VERSION");
    bool is_kde = (desktop_env && strstr(desktop_env, "KDE")) || kde_session;
    
    std::string dialog_cmd;
    
    if (is_kde) {
        // KDE: Use kdialog
        dialog_cmd = "kdialog --getopenfilename . ";
        
        if (filters && filter_count > 0) {
            dialog_cmd += "'";
            for (int i = 0; i < filter_count; i++) {
                if (i > 0) dialog_cmd += "|";
                dialog_cmd += filters[i].name;
                dialog_cmd += " (";
                
                // Convert extensions to kdialog format
                std::string exts = filters[i].extensions;
                if (exts != "*") {
                    size_t pos = 0;
                    std::string token;
                    bool first = true;
                    while ((pos = exts.find(',')) != std::string::npos) {
                        token = exts.substr(0, pos);
                        if (!first) dialog_cmd += " ";
                        dialog_cmd += "*." + token;
                        first = false;
                        exts.erase(0, pos + 1);
                    }
                    if (!exts.empty()) {
                        if (!first) dialog_cmd += " ";
                        dialog_cmd += "*." + exts;
                    }
                } else {
                    dialog_cmd += "*";
                }
                dialog_cmd += ")";
            }
            dialog_cmd += "'";
        } else {
            dialog_cmd += "'All files (*)'";
        }
        
        dialog_cmd += " --title '" + title + "' 2>/dev/null";
    } else {
        // GNOME/others: Use zenity
        dialog_cmd = "zenity --file-selection --title='" + title + "'";
        
        if (filters && filter_count > 0) {
            for (int i = 0; i < filter_count; i++) {
                dialog_cmd += " --file-filter='" + std::string(filters[i].name) + " | ";
                
                // Convert extensions to zenity format
                std::string exts = filters[i].extensions;
                if (exts != "*") {
                    size_t pos = 0;
                    std::string token;
                    bool first = true;
                    while ((pos = exts.find(',')) != std::string::npos) {
                        token = exts.substr(0, pos);
                        if (!first) dialog_cmd += " ";
                        dialog_cmd += "*." + token;
                        first = false;
                        exts.erase(0, pos + 1);
                    }
                    if (!exts.empty()) {
                        if (!first) dialog_cmd += " ";
                        dialog_cmd += "*." + exts;
                    }
                } else {
                    dialog_cmd += "*";
                }
                dialog_cmd += "'";
            }
        }
        
        dialog_cmd += " 2>/dev/null";
    }
    
    FILE *fp = popen(dialog_cmd.c_str(), "r");
    if (fp) {
        char path_buffer[4096];
        if (fgets(path_buffer, sizeof(path_buffer), fp)) {
            size_t len = strlen(path_buffer);
            if (len > 0 && path_buffer[len-1] == '\n') {
                path_buffer[len-1] = '\0';
            }
            if (strlen(path_buffer) > 0) {
                pclose(fp);
                return std::string(path_buffer);
            }
        }
        int status = pclose(fp);
        if (status != 0) {
            last_error = is_kde 
                ? "Error: kdialog not found. Install kdialog package."
                : "Error: zenity not found. Install zenity package.";
        }
    } else {
        last_error = is_kde
            ? "Error: Failed to launch kdialog"
            : "Error: Failed to launch zenity";
    }
#endif
    
    return "";
}

std::string saveFileDialog(const std::string& title, const std::string& default_name, FileType type) {
    last_error.clear();
    
#ifdef _WIN32
    // Windows: Use NFD
    nfdchar_t *outPath = nullptr;
    nfdresult_t result;
    
    const FileFilter* filters = nullptr;
    int filter_count = 0;
    
    switch (type) {
        case FILE_TYPE_IMAGES:
            filters = IMAGE_FILTERS;
            filter_count = 1;
            break;
        case FILE_TYPE_WALLETS:
            filters = WALLET_FILTERS;
            filter_count = 2;
            break;
    }
    
    if (filters && filter_count > 0) {
        nfdfilteritem_t* nfd_filters = new nfdfilteritem_t[filter_count];
        for (int i = 0; i < filter_count; i++) {
            nfd_filters[i].name = filters[i].name;
            nfd_filters[i].spec = filters[i].extensions;
        }
        result = NFD_SaveDialog(&outPath, nfd_filters, filter_count, nullptr, default_name.c_str());
        delete[] nfd_filters;
    } else {
        result = NFD_SaveDialog(&outPath, nullptr, 0, nullptr, default_name.c_str());
    }
    
    if (result == NFD_OKAY) {
        std::string path(outPath);
        NFD_FreePath(outPath);
        return path;
    } else if (result == NFD_ERROR) {
        last_error = "File dialog error: ";
        last_error += NFD_GetError();
    }
    
#else
    // Linux: Use save dialog
    const char *desktop_env = getenv("XDG_CURRENT_DESKTOP");
    const char *kde_session = getenv("KDE_SESSION_VERSION");
    bool is_kde = (desktop_env && strstr(desktop_env, "KDE")) || kde_session;
    
    std::string dialog_cmd;
    
    if (is_kde) {
        dialog_cmd = "kdialog --getsavefilename . --title '" + title + "'";
        if (!default_name.empty()) {
            dialog_cmd = "kdialog --getsavefilename ./" + default_name + " --title '" + title + "'";
        }
    } else {
        dialog_cmd = "zenity --file-selection --save --title='" + title + "'";
        if (!default_name.empty()) {
            dialog_cmd += " --filename='" + default_name + "'";
        }
    }
    
    dialog_cmd += " 2>/dev/null";
    
    FILE *fp = popen(dialog_cmd.c_str(), "r");
    if (fp) {
        char path_buffer[4096];
        if (fgets(path_buffer, sizeof(path_buffer), fp)) {
            size_t len = strlen(path_buffer);
            if (len > 0 && path_buffer[len-1] == '\n') {
                path_buffer[len-1] = '\0';
            }
            if (strlen(path_buffer) > 0) {
                pclose(fp);
                return std::string(path_buffer);
            }
        }
        pclose(fp);
    }
#endif
    
    return "";
}

void openFileDialogAsync(AsyncTask* task, const std::string& title, FileType type) {
    async_result.clear();
    async_result = openFileDialog(title, type);
}

std::string getAsyncResult() {
    return async_result;
}

} // namespace FileBrowser