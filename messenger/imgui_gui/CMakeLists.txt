cmake_minimum_required(VERSION 3.10)

# ImGui GUI for DNA Messenger
project(dna_messenger_imgui CXX)

set(CMAKE_CXX_STANDARD 17)

# Enable wide character support for emoji (U+10000+)
add_definitions(-DIMGUI_USE_WCHAR32)
# Enable FreeType for colored emoji
add_definitions(-DIMGUI_ENABLE_FREETYPE)

# Prefer GLVND for OpenGL (suppresses legacy GL warning)
set(OpenGL_GL_PREFERENCE GLVND)

# Find required packages
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)
find_package(Freetype REQUIRED)

# ImGui source files
set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/imgui)
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    ${IMGUI_DIR}/misc/freetype/imgui_freetype.cpp
)

# QR code generator
set(QRCODEGEN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/qrcodegen)
set(QRCODEGEN_SOURCES
    ${QRCODEGEN_DIR}/qrcodegen.cpp
)

# Native File Dialog Extended
set(NFD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/nativefiledialog-extended/src)
if(UNIX AND NOT APPLE)
    set(NFD_SOURCES ${NFD_DIR}/nfd_gtk.cpp)
elseif(APPLE)
    set(NFD_SOURCES ${NFD_DIR}/nfd_cocoa.m)
elseif(WIN32)
    set(NFD_SOURCES ${NFD_DIR}/nfd_win.cpp)
endif()

# Main application
add_executable(dna_messenger_imgui
    main.cpp
    app.cpp
    settings_manager.cpp
    ui_helpers.cpp
    texture_manager.cpp
    core/app_state.cpp
    helpers/data_loader.cpp
    helpers/avatar_helpers.cpp
    screens/register_name_screen.cpp
    screens/message_wall_screen.cpp
    screens/profile_editor_screen.cpp
    screens/contact_profile_viewer.cpp
    screens/settings_screen.cpp
    screens/wallet_receive_dialog.cpp
    screens/wallet_send_dialog.cpp
    screens/wallet_transaction_history_dialog.cpp
    screens/wallet_screen.cpp
    screens/add_contact_dialog.cpp
    screens/create_group_dialog.cpp
    screens/group_invitation_dialog.cpp
    screens/chat_screen.cpp
    screens/contacts_sidebar.cpp
    screens/identity_selection_screen.cpp
    screens/layout_manager.cpp
    ${IMGUI_SOURCES}
    ${QRCODEGEN_SOURCES}
    ${NFD_SOURCES}
)

target_include_directories(dna_messenger_imgui PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMGUI_DIR}/misc/freetype
    ${FREETYPE_INCLUDE_DIRS}
    ${QRCODEGEN_DIR}
    ${NFD_DIR}/include
)

target_link_libraries(dna_messenger_imgui PRIVATE
    OpenGL::GL
    glfw
    dna_lib  # DNA Messenger core library
    cellframe_minimal  # Transaction building and signing
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(dna_messenger_imgui PRIVATE
        opengl32
        gdi32
        harfbuzz
        ${FREETYPE_LIBRARIES}
        harfbuzz
        png
        z
        bz2
        ole32  # Required for NFD on Windows
        uuid  # Required for NFD on Windows
    )
else()
    # Find GTK3 for NFD on Linux
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
    
    target_link_libraries(dna_messenger_imgui PRIVATE
        ${FREETYPE_LIBRARIES}
        ${GTK3_LIBRARIES}
    )
    target_include_directories(dna_messenger_imgui PRIVATE ${GTK3_INCLUDE_DIRS})
endif()

# Install emoji font to ~/.dna/fonts (Linux) or %APPDATA%\.dna\fonts (Windows)
if(WIN32)
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/fonts/NotoColorEmoji.ttf 
            DESTINATION "$ENV{APPDATA}/.dna/fonts")
else()
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/fonts/NotoColorEmoji.ttf 
            DESTINATION "$ENV{HOME}/.dna/fonts")
endif()

# Install
install(TARGETS dna_messenger_imgui DESTINATION bin)
