// DNA Messenger - ImGui GUI
// Modern, lightweight, cross-platform messenger interface

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <string>
#include <vector>

extern "C" {
#include "../dna_api.h"
#include "../messenger_p2p.h"
#include "../wallet.h"
}

struct Message {
    std::string sender;
    std::string content;
    std::string timestamp;
    bool is_outgoing;
};

struct Contact {
    std::string name;
    std::string address;
    bool is_online;
};

class DNAMessengerApp {
public:
    DNAMessengerApp() {
        current_view = VIEW_CHAT;
        selected_contact = -1;
        show_wallet = false;
    }

    void render() {
        ImGuiIO& io = ImGui::GetIO();
        
        // Main window
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("DNA Messenger", nullptr, 
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        // Sidebar (contacts + navigation)
        renderSidebar();
        
        ImGui::SameLine();
        
        // Main content area
        ImGui::BeginChild("MainContent", ImVec2(0, 0), true);
        
        switch(current_view) {
            case VIEW_CHAT:
                renderChatView();
                break;
            case VIEW_WALLET:
                renderWalletView();
                break;
            case VIEW_SETTINGS:
                renderSettingsView();
                break;
        }
        
        ImGui::EndChild();
        
        ImGui::End();
    }

private:
    enum View {
        VIEW_CHAT,
        VIEW_WALLET,
        VIEW_SETTINGS
    };

    View current_view;
    int selected_contact;
    bool show_wallet;
    
    std::vector<Contact> contacts;
    std::vector<Message> messages;
    char message_input[1024] = "";
    
    void renderSidebar() {
        ImGui::BeginChild("Sidebar", ImVec2(250, 0), true);
        
        ImGui::Text("DNA Messenger");
        ImGui::Separator();
        
        // Navigation buttons
        if (ImGui::Button("💬 Chat", ImVec2(-1, 40))) {
            current_view = VIEW_CHAT;
        }
        if (ImGui::Button("💰 Wallet", ImVec2(-1, 40))) {
            current_view = VIEW_WALLET;
        }
        if (ImGui::Button("⚙️ Settings", ImVec2(-1, 40))) {
            current_view = VIEW_SETTINGS;
        }
        
        ImGui::Separator();
        ImGui::Text("Contacts");
        ImGui::Separator();
        
        // Contact list
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            // Online indicator
            ImVec4 color = contacts[i].is_online ? 
                ImVec4(0.0f, 1.0f, 0.0f, 1.0f) : ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
            ImGui::TextColored(color, "●");
            ImGui::SameLine();
            
            if (ImGui::Selectable(contacts[i].name.c_str(), 
                selected_contact == (int)i, 0, ImVec2(-1, 30))) {
                selected_contact = i;
            }
            
            ImGui::PopID();
        }
        
        // Add contact button at bottom
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 40);
        if (ImGui::Button("➕ Add Contact", ImVec2(-1, 30))) {
            // TODO: Open add contact dialog
        }
        
        ImGui::EndChild();
    }
    
    void renderChatView() {
        if (selected_contact < 0 || selected_contact >= (int)contacts.size()) {
            ImGui::Text("Select a contact to start chatting");
            return;
        }
        
        Contact& contact = contacts[selected_contact];
        
        // Chat header
        ImGui::Text("Chat with %s", contact.name.c_str());
        ImGui::SameLine();
        ImGui::TextColored(
            contact.is_online ? ImVec4(0.0f, 1.0f, 0.0f, 1.0f) : ImVec4(0.5f, 0.5f, 0.5f, 1.0f),
            contact.is_online ? "Online" : "Offline"
        );
        ImGui::Separator();
        
        // Message area
        ImGui::BeginChild("MessageArea", ImVec2(0, -70), true);
        
        for (const auto& msg : messages) {
            if (msg.is_outgoing) {
                ImGui::Indent(ImGui::GetWindowWidth() * 0.3f);
            }
            
            ImGui::PushStyleColor(ImGuiCol_ChildBg, 
                msg.is_outgoing ? ImVec4(0.2f, 0.6f, 0.8f, 0.3f) : ImVec4(0.3f, 0.3f, 0.3f, 0.3f));
            
            ImGui::BeginChild(("msg" + std::to_string(&msg - &messages[0])).c_str(), 
                ImVec2(ImGui::GetWindowWidth() * 0.6f, 0), true, ImGuiWindowFlags_AlwaysAutoResize);
            
            ImGui::TextWrapped("%s", msg.content.c_str());
            ImGui::TextDisabled("%s", msg.timestamp.c_str());
            
            ImGui::EndChild();
            ImGui::PopStyleColor();
            
            if (msg.is_outgoing) {
                ImGui::Unindent(ImGui::GetWindowWidth() * 0.3f);
            }
        }
        
        ImGui::EndChild();
        
        // Message input
        ImGui::Separator();
        ImGui::InputTextMultiline("##MessageInput", message_input, 
            sizeof(message_input), ImVec2(-80, 60));
        ImGui::SameLine();
        
        if (ImGui::Button("Send", ImVec2(70, 60))) {
            if (strlen(message_input) > 0) {
                // TODO: Send message via DNA API
                Message msg;
                msg.content = message_input;
                msg.is_outgoing = true;
                msg.timestamp = "Now";
                messages.push_back(msg);
                message_input[0] = '\0';
            }
        }
    }
    
    void renderWalletView() {
        ImGui::Text("💰 cpunk Wallet");
        ImGui::Separator();
        
        // Token balances
        ImGui::BeginChild("Balances", ImVec2(0, 200), true);
        ImGui::Text("CPUNK: 0.00");
        ImGui::Text("CELL: 0.00");
        ImGui::Text("KEL: 0.00");
        ImGui::EndChild();
        
        ImGui::Spacing();
        
        // Wallet actions
        if (ImGui::Button("Send Tokens", ImVec2(150, 40))) {
            // TODO: Open send dialog
        }
        ImGui::SameLine();
        if (ImGui::Button("Receive", ImVec2(150, 40))) {
            // TODO: Show receive address
        }
        ImGui::SameLine();
        if (ImGui::Button("History", ImVec2(150, 40))) {
            // TODO: Show transaction history
        }
    }
    
    void renderSettingsView() {
        ImGui::Text("⚙️ Settings");
        ImGui::Separator();
        
        static int theme = 0;
        ImGui::RadioButton("cpunk.io (Cyan)", &theme, 0);
        ImGui::RadioButton("cpunk.club (Orange)", &theme, 1);
        ImGui::RadioButton("Dark Mode", &theme, 2);
        
        ImGui::Spacing();
        ImGui::Separator();
        
        ImGui::Text("Identity: (not loaded)");
        if (ImGui::Button("Create New Identity")) {
            // TODO: Create identity dialog
        }
        ImGui::SameLine();
        if (ImGui::Button("Import Identity")) {
            // TODO: Import identity dialog
        }
    }
};

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "DNA Messenger", nullptr, nullptr);
    if (window == nullptr)
        return 1;

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    
    // Custom theme colors (cpunk.io cyan)
    ImGuiStyle& style = ImGui::GetStyle();
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.1f, 0.1f, 0.1f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.0f, 0.8f, 0.8f, 0.4f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.0f, 1.0f, 1.0f, 0.6f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.0f, 0.8f, 0.8f, 1.0f);
    style.FrameRounding = 4.0f;
    style.WindowRounding = 8.0f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    DNAMessengerApp app;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        app.render();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
