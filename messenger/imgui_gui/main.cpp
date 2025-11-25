// DNA Messenger - ImGui GUI
// Modern, lightweight, cross-platform messenger interface
// UI SKETCH MODE - Backend integration disabled for UI development

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_freetype.h"
#include "modal_helper.h"
#include "font_awesome.h"
#include "theme_colors.h"
#include "settings_manager.h"
#include "ui_helpers.h"
#include "app.h"
#include "helpers/async_helpers.h"
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <signal.h>

// Backend includes
extern "C" {
    #include "../dht/client/dht_singleton.h"
    #include "../dht/core/dht_keyserver.h"
    #include "../crypto/utils/qgp_platform.h"
}
#include "helpers/data_loader.h"
#include "screens/wallet_screen.h"
#include "screens/profile_editor_screen.h"
#ifdef _WIN32
#include <nfd.h>
#endif
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include <chrono>
#include <thread>
#include <atomic>

#ifndef _WIN32
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <windows.h>
#include <direct.h>
#endif

// Global flag for clean shutdown
static volatile bool g_should_quit = false;
static volatile bool g_glfw_initialized = false;
static std::chrono::steady_clock::time_point g_shutdown_start_time;

// Signal handler for Ctrl+C and other termination signals
void signal_handler(int signum) {
    static int signal_count = 0;
    signal_count++;
    
    if (signal_count == 1) {
        printf("\n[MAIN] Received signal %d, shutting down gracefully...\n", signum);
        g_should_quit = true;
        g_shutdown_start_time = std::chrono::steady_clock::now();
        
        // Wake up the event loop immediately to process the shutdown (only if GLFW is ready)
        if (g_glfw_initialized) {
            glfwPostEmptyEvent();
        } else {
            // If GLFW not ready yet, force exit immediately
            printf("[MAIN] GLFW not initialized, forcing immediate exit...\n");
            exit(0);
        }
    } else {
        // Multiple Ctrl+C presses - force immediate exit
        printf("\n[MAIN] Received signal %d again, forcing immediate exit...\n", signum);
        exit(1);
    }
}

// Backend includes for full functionality
extern "C" {
#include "../dna_api.h"
#include "../messenger_p2p.h"
#include "../messenger.h"
#include "../blockchain/wallet.h"
#include "../crypto/bip39/bip39.h"
#include "../dht/client/dna_message_wall.h"
#include "../dht/client/dna_profile.h"
#include "../p2p/p2p_transport.h"
}

// Global settings
AppSettings g_app_settings;

// Apply theme colors to ImGui
void ApplyTheme(int theme) {
    ImGuiStyle& style = ImGui::GetStyle();

    if (theme == 0) { // DNA Theme
        style.Colors[ImGuiCol_Text] = DNATheme::Text();
        style.Colors[ImGuiCol_TextDisabled] = DNATheme::TextDisabled();
        style.Colors[ImGuiCol_WindowBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ChildBg] = DNATheme::Background();
        style.Colors[ImGuiCol_PopupBg] = DNATheme::Background();
        style.Colors[ImGuiCol_Border] = DNATheme::Border();
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_FrameBg] = ImVec4(0.12f, 0.14f, 0.16f, 1.0f); // Dark grey for input contrast
        style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.14f, 0.16f, 0.18f, 1.0f);
        style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.16f, 0.18f, 0.20f, 1.0f);
        style.Colors[ImGuiCol_TitleBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TitleBgActive] = DNATheme::Background();
        style.Colors[ImGuiCol_TitleBgCollapsed] = DNATheme::Background();
        style.Colors[ImGuiCol_MenuBarBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ScrollbarBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ScrollbarGrab] = DNATheme::Text();
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ScrollbarGrabActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_CheckMark] = DNATheme::Text(); // Checkmark and radio button should match text color
        style.Colors[ImGuiCol_SliderGrab] = DNATheme::Text();
        style.Colors[ImGuiCol_SliderGrabActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Button] = DNATheme::Text();
        style.Colors[ImGuiCol_ButtonHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ButtonActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Header] = ImVec4(0.0f, 1.0f, 0.8f, 0.2f); // 20% opacity
        style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.0f, 1.0f, 0.8f, 0.4f); // 40% opacity - visible but not too bright
        style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.0f, 1.0f, 0.8f, 0.5f); // 50% opacity
        style.Colors[ImGuiCol_Separator] = DNATheme::Separator();
        style.Colors[ImGuiCol_SeparatorHovered] = DNATheme::Text();
        style.Colors[ImGuiCol_SeparatorActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_ResizeGrip] = DNATheme::Text();
        style.Colors[ImGuiCol_ResizeGripHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ResizeGripActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Tab] = DNATheme::Background();
        style.Colors[ImGuiCol_TabHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TabSelected] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_TabSelectedOverline] = DNATheme::Text();
        style.Colors[ImGuiCol_TabDimmed] = DNATheme::Background();
        style.Colors[ImGuiCol_TabDimmedSelected] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TabDimmedSelectedOverline] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_PlotLines] = DNATheme::Text();
        style.Colors[ImGuiCol_PlotLinesHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_PlotHistogram] = DNATheme::Text();
        style.Colors[ImGuiCol_PlotHistogramHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TableHeaderBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TableBorderStrong] = DNATheme::Border();
        style.Colors[ImGuiCol_TableBorderLight] = DNATheme::Border();
        style.Colors[ImGuiCol_TableRowBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TableRowBgAlt] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TextSelectedBg] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_DragDropTarget] = DNATheme::Text();
        style.Colors[ImGuiCol_NavHighlight] = DNATheme::Text();
        style.Colors[ImGuiCol_NavWindowingHighlight] = DNATheme::Text();
        style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.2f);
        style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.35f);
        
        // Set frame border for checkboxes/radio buttons
        style.FrameBorderSize = DNATheme::FrameBorderSize();
    } else { // Club Theme
        style.Colors[ImGuiCol_Text] = ClubTheme::Text();
        style.Colors[ImGuiCol_TextDisabled] = ClubTheme::TextDisabled();
        style.Colors[ImGuiCol_WindowBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ChildBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_PopupBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_Border] = ClubTheme::Border();
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.14f, 0.13f, 1.0f); // Dark grey for input contrast
        style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.17f, 0.16f, 0.15f, 1.0f);
        style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.19f, 0.18f, 0.17f, 1.0f);
        style.Colors[ImGuiCol_TitleBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TitleBgActive] = ClubTheme::Background();
        style.Colors[ImGuiCol_TitleBgCollapsed] = ClubTheme::Background();
        style.Colors[ImGuiCol_MenuBarBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ScrollbarBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ScrollbarGrab] = ClubTheme::Text();
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ScrollbarGrabActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_CheckMark] = ClubTheme::Text(); // Checkmark and radio button should match text color
        style.Colors[ImGuiCol_SliderGrab] = ClubTheme::Text();
        style.Colors[ImGuiCol_SliderGrabActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Button] = ClubTheme::Text();
        style.Colors[ImGuiCol_ButtonHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ButtonActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Header] = ImVec4(0.976f, 0.471f, 0.204f, 0.2f); // 20% opacity
        style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.976f, 0.471f, 0.204f, 0.4f); // 40% opacity - visible but not too bright
        style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.976f, 0.471f, 0.204f, 0.5f); // 50% opacity
        style.Colors[ImGuiCol_Separator] = ClubTheme::Separator();
        style.Colors[ImGuiCol_SeparatorHovered] = ClubTheme::Text();
        style.Colors[ImGuiCol_SeparatorActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_ResizeGrip] = ClubTheme::Text();
        style.Colors[ImGuiCol_ResizeGripHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ResizeGripActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Tab] = ClubTheme::Background();
        style.Colors[ImGuiCol_TabHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TabSelected] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_TabSelectedOverline] = ClubTheme::Text();
        style.Colors[ImGuiCol_TabDimmed] = ClubTheme::Background();
        style.Colors[ImGuiCol_TabDimmedSelected] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TabDimmedSelectedOverline] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_PlotLines] = ClubTheme::Text();
        style.Colors[ImGuiCol_PlotLinesHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_PlotHistogram] = ClubTheme::Text();
        style.Colors[ImGuiCol_PlotHistogramHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TableHeaderBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TableBorderStrong] = ClubTheme::Border();
        style.Colors[ImGuiCol_TableBorderLight] = ClubTheme::Border();
        style.Colors[ImGuiCol_TableRowBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TableRowBgAlt] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TextSelectedBg] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_DragDropTarget] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavHighlight] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavWindowingHighlight] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.2f);
        style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.35f);
        
        // Set frame border for checkboxes/radio buttons
        style.FrameBorderSize = ClubTheme::FrameBorderSize();
    }
}



static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    // Register signal handlers for clean shutdown
    signal(SIGINT, signal_handler);   // Ctrl+C
    signal(SIGTERM, signal_handler);  // Termination request
#ifndef _WIN32
    signal(SIGHUP, signal_handler);   // Terminal closed (Unix)
#endif
    printf("[MAIN] Signal handlers registered (Ctrl+C for clean exit)\n");

    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;
    
    g_glfw_initialized = true;  // Mark GLFW as ready for signal handling

    #ifdef _WIN32
    // Initialize NFD (Windows only - Linux uses zenity/kdialog)
    if (NFD_Init() != NFD_OKAY) {
        fprintf(stderr, "[MAIN] NFD initialization failed: %s\n", NFD_GetError());
        return 1;
    }
    printf("[MAIN] NFD initialized successfully\n");
    #endif

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Keep window decorated for X11 compatibility (borderless mode causes crashes)
    // glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);

    // Load settings from file
    SettingsManager::Load(g_app_settings);
    printf("[SKETCH MODE] Settings loaded: theme=%d, window=%dx%d\n",
           g_app_settings.theme, g_app_settings.window_width, g_app_settings.window_height);

    GLFWwindow* window = glfwCreateWindow(g_app_settings.window_width, g_app_settings.window_height, "DNA Messenger", nullptr, nullptr);
    if (window == nullptr)
        return 1;

    // Set minimum window size for desktop
    glfwSetWindowSizeLimits(window, 1000, 600, GLFW_DONT_CARE, GLFW_DONT_CARE);

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "dna_messenger.ini"; // Enable INI saving

        // Load embedded fonts
    #include "fonts/NotoSans-Regular.h"
    #include "fonts/fa-solid-900.h"

    ImFontConfig config;
    config.MergeMode = false;
    config.FontDataOwnedByAtlas = false; // Don't let ImGui free our static embedded data

    // Base font size (will be scaled by ui_scale via FontScaleMain)
    float base_size = 18.0f;
    io.Fonts->AddFontFromMemoryTTF((void*)NotoSans_Regular_ttf, sizeof(NotoSans_Regular_ttf), base_size, &config);

    // Merge Font Awesome icons
    config.MergeMode = true;
    config.GlyphMinAdvanceX = base_size;
    config.GlyphOffset = ImVec2(0, 2);
    config.FontDataOwnedByAtlas = false;
    static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    io.Fonts->AddFontFromMemoryTTF((void*)fa_solid_900_ttf, sizeof(fa_solid_900_ttf), base_size * 0.9f, &config, icon_ranges);

    ImGui::StyleColorsDark();

    // DNA Messenger styling
    ImGuiStyle& style = ImGui::GetStyle();

    // Rounding
    style.FrameRounding = 4.0f;
    style.WindowRounding = 8.0f;
    style.ChildRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;

    // Selective borders: keep child borders (sidebar), remove others
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;  // Keep this for sidebar

    // Apply initial theme (DNA theme by default)
    ApplyTheme(g_app_settings.theme);
    
    // Apply native ImGui scaling (fonts + UI elements)
    style.ScaleAllSizes(g_app_settings.ui_scale);
    style.FontScaleMain = g_app_settings.ui_scale;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    DNAMessengerApp app;

    // Initialize global DHT singleton with loading screen (async)
    AsyncTask dht_init_task;
    float dht_loading_start_time = 0.0f;
    bool dht_loading_started = false;

    // Track fullscreen state
    static bool is_fullscreen = false;
    static int windowed_xpos, windowed_ypos, windowed_width, windowed_height;
    static bool f11_was_pressed = false;

    while (!glfwWindowShouldClose(window) && !g_should_quit) {
        // Always use PollEvents + sleep for reliable signal handling
        glfwPollEvents();
        
        // Small sleep to prevent busy waiting but allow responsive signal handling
        std::this_thread::sleep_for(std::chrono::milliseconds(16)); // ~60 FPS
        
        // Check if signal was received
        if (g_should_quit) {
            printf("[MAIN] Shutdown signal received, breaking main loop...\n");
            
            // Check if shutdown is taking too long (force exit after 3 seconds)
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_shutdown_start_time);
            if (elapsed.count() > 3000) {
                printf("[MAIN] Shutdown timeout exceeded, forcing exit...\n");
                exit(1);
            }
            break;
        }
        
        // F11 to toggle fullscreen (process BEFORE loading screen so it works immediately)
        if (glfwGetKey(window, GLFW_KEY_F11) == GLFW_PRESS) {
            if (!f11_was_pressed) {
                f11_was_pressed = true;
                
                if (!is_fullscreen) {
                    // Save windowed position and size
                    glfwGetWindowPos(window, &windowed_xpos, &windowed_ypos);
                    glfwGetWindowSize(window, &windowed_width, &windowed_height);
                    
                    // Switch to fullscreen
                    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
                    const GLFWvidmode* mode = glfwGetVideoMode(monitor);
                    glfwSetWindowMonitor(window, monitor, 0, 0, mode->width, mode->height, mode->refreshRate);
                    is_fullscreen = true;
                } else {
                    // Restore windowed mode
                    glfwSetWindowMonitor(window, nullptr, windowed_xpos, windowed_ypos, windowed_width, windowed_height, 0);
                    is_fullscreen = false;
                }
            }
        } else {
            f11_was_pressed = false;
        }
        
        // Start DHT init on first frame
        if (!dht_loading_started) {
            dht_loading_started = true;
            dht_loading_start_time = (float)glfwGetTime();
            
            // Start DHT init in background thread
            dht_init_task.start([&app](AsyncTask* task) {
                printf("[MAIN] DHT initialization will happen asynchronously...\n");
                
                if (dht_singleton_init() != 0) {
                    fprintf(stderr, "[MAIN] ERROR: Failed to initialize DHT network\n");
                } else {
                    printf("[MAIN] [OK] DHT ready!\n");
                    
                    // Preload identity names while still on loading screen
                    printf("[MAIN] Preloading identity names...\n");
                    AppState& state = app.getState();
                    DataLoader::scanIdentities(state);

                    // BUGFIX: Always mark identities as scanned, even if empty
                    state.identities_scanned = true;

                    dht_context_t *dht_ctx = dht_singleton_get();
                    if (dht_ctx && !state.identities.empty()) {
                        // Track completed lookups with atomic counter
                        std::atomic<size_t> completed_lookups(0);
                        size_t total_lookups = 0;
                        
                        for (const auto& fp : state.identities) {
                            if (fp.length() == 128 && state.identity_name_cache.find(fp) == state.identity_name_cache.end()) {
                                // Initialize with shortened fingerprint (fallback)
                                state.identity_name_cache[fp] = fp.substr(0, 10) + "..." + fp.substr(fp.length() - 10);
                                
                                // Start async DHT reverse lookup
                                total_lookups++;
                                
                                struct lookup_ctx {
                                    AppState *state_ptr;
                                    char fingerprint[129];
                                    std::atomic<size_t> *completed_ptr;
                                };
                                
                                lookup_ctx *ctx = new lookup_ctx;
                                ctx->state_ptr = &state;
                                ctx->completed_ptr = &completed_lookups;
                                strncpy(ctx->fingerprint, fp.c_str(), 128);
                                ctx->fingerprint[128] = '\0';
                                
                                dht_keyserver_reverse_lookup_async(dht_ctx, fp.c_str(),
                                    [](char *registered_name, void *userdata) {
                                        lookup_ctx *ctx = (lookup_ctx*)userdata;
                                        
                                        if (registered_name) {
                                            std::string fp_str(ctx->fingerprint);
                                            printf("[MAIN] DHT lookup: %s → %s\n", fp_str.substr(0, 16).c_str(), registered_name);
                                            ctx->state_ptr->identity_name_cache[fp_str] = std::string(registered_name);
                                            free(registered_name);
                                        }
                                        
                                        // Mark this lookup as completed
                                        (*ctx->completed_ptr)++;
                                        
                                        delete ctx;
                                    },
                                    ctx);
                            }
                        }
                        
                        printf("[MAIN] Started %zu identity name lookups\n", total_lookups);
                        
                        // Wait for all lookups to complete (with timeout)
                        if (total_lookups > 0) {
                            const int max_wait_ms = 3000; // 3 second timeout
                            const int poll_interval_ms = 50;
                            int waited_ms = 0;
                            
                            while (completed_lookups < total_lookups && waited_ms < max_wait_ms) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms));
                                waited_ms += poll_interval_ms;
                            }
                            
                            printf("[MAIN] Completed %zu/%zu lookups in %dms\n",
                                   completed_lookups.load(), total_lookups, waited_ms);
                        }

                        // Preload wallet data asynchronously (non-blocking)
                        printf("[MAIN] Preloading wallet data...\n");
                        state.wallet_preload_task.start([&state](AsyncTask* task) {
                            WalletScreen::loadWallet(state);
                            if (state.wallet_loaded) {
                                WalletScreen::preloadAllBalances(state);
                                printf("[MAIN] Wallet data preloaded successfully\n");
                            } else {
                                printf("[MAIN] No wallets found to preload\n");
                            }
                        });

                        // NOTE: Profile preload moved to after identity is loaded and DHT reinitializes
                        // with user identity. This prevents race condition with DHT stabilization.
                        // See app.cpp loadIdentity() for profile preload invocation.
                    }
                }
            });
        }
        
        // Show loading screen until DHT ready AND identities scanned
        float elapsed = (float)glfwGetTime() - dht_loading_start_time;
        bool show_loading = dht_init_task.isRunning() || !app.areIdentitiesReady() || elapsed < 0.5f;
        
        if (show_loading) {
            // Show loading screen
            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();
            
            // Full-screen loading spinner
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("Loading", nullptr, 
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);
            
            // Center spinner at fixed position
            float spinner_radius = 40.0f;
            ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
            ImGui::SetCursorScreenPos(ImVec2(center.x - spinner_radius, center.y - spinner_radius));
            ThemedSpinner("dht_loading", spinner_radius, 6.0f);
            
            // Simple loading text below spinner
            const char* loading_text = "Starting DNA Messenger...";
            ImVec2 text_size = ImGui::CalcTextSize(loading_text);
            float text_y = center.y + spinner_radius + 30.0f;
            ImGui::SetCursorScreenPos(ImVec2(center.x - text_size.x * 0.5f, text_y));
            ImGui::Text("%s", loading_text);
            
            ImGui::End();
            
            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            glfwSwapBuffers(window);
            continue;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        app.render();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f); // #151719
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Save window size before exit
    int width, height;
    glfwGetWindowSize(window, &width, &height);
    g_app_settings.window_width = width;
    g_app_settings.window_height = height;
    SettingsManager::Save(g_app_settings);

    // Cleanup global DHT singleton on app shutdown with timeout
    printf("[MAIN] Cleaning up DHT singleton...\n");
    auto cleanup_start = std::chrono::steady_clock::now();
    
    // Run cleanup in a separate thread with timeout
    std::atomic<bool> cleanup_done{false};
    std::thread cleanup_thread([&cleanup_done]() {
        dht_singleton_cleanup();
        cleanup_done = true;
    });
    
    // Wait for cleanup with timeout
    while (!cleanup_done) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - cleanup_start);
        if (elapsed.count() > 2000) { // 2 second timeout
            printf("[MAIN] DHT cleanup timeout, forcing exit...\n");
            cleanup_thread.detach(); // Let it finish in background
            exit(0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    cleanup_thread.join();
    printf("[MAIN] DHT cleanup completed\n");

    printf("[MAIN] Shutting down ImGui...\n");
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    #ifdef _WIN32
    printf("[MAIN] Shutting down NFD...\n");
    NFD_Quit();
    #endif

    printf("[MAIN] Destroying window...\n");
    glfwDestroyWindow(window);
    glfwTerminate();

    printf("[MAIN] [OK] Clean shutdown complete\n");
    return 0;
}
