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

if(WIN32)
    # Windows cross-compile: GLFW found via CMAKE_PREFIX_PATH (llvm-mingw)
    # CMAKE_PREFIX_PATH is set in main CMakeLists.txt to point to llvm-mingw x86_64-w64-mingw32/
    find_library(GLFW3_LIB glfw3 REQUIRED)
    set(GLFW3_INCLUDE_DIRS "${CMAKE_PREFIX_PATH}/include")
    set(GLFW3_LIBRARIES "${GLFW3_LIB}")
    message(STATUS "Using GLFW from CMAKE_PREFIX_PATH for Windows (GUI)")
    message(STATUS "GLFW include: ${GLFW3_INCLUDE_DIRS}")
    message(STATUS "GLFW library: ${GLFW3_LIBRARIES}")
else()
    # Linux/Mac: Use find_package
    find_package(glfw3 REQUIRED)
endif()

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

# Native File Dialog Extended (Windows only, Linux uses zenity/kdialog)
set(NFD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/nativefiledialog-extended/src)
if(APPLE)
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
    helpers/notification_manager.cpp
    helpers/background_tasks.cpp
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
)

# Add NFD sources only on Windows
if(WIN32)
    target_sources(dna_messenger_imgui PRIVATE ${NFD_SOURCES})
endif()

target_include_directories(dna_messenger_imgui PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMGUI_DIR}/misc/freetype
    ${FREETYPE_INCLUDE_DIRS}
    ${QRCODEGEN_DIR}
    ${NFD_DIR}/include
)

# Add GLFW include directories for Windows (manually set)
if(WIN32)
    target_include_directories(dna_messenger_imgui PRIVATE ${GLFW3_INCLUDE_DIRS})
endif()

target_link_libraries(dna_messenger_imgui PRIVATE
    OpenGL::GL
    dna_lib  # DNA Messenger core library
    cellframe_minimal  # Transaction building and signing
)

# Link GLFW library (platform-specific)
if(WIN32)
    target_link_libraries(dna_messenger_imgui PRIVATE ${GLFW3_LIBRARIES})
else()
    target_link_libraries(dna_messenger_imgui PRIVATE glfw)
endif()

# Platform-specific settings
if(WIN32)
    target_link_libraries(dna_messenger_imgui PRIVATE
        opengl32
        gdi32
        ${FREETYPE_LIBRARIES}
        z  # zlib (required by Freetype for gzip support)
        ole32  # Required for NFD on Windows
        uuid  # Required for NFD on Windows
    )
else()
    target_link_libraries(dna_messenger_imgui PRIVATE
        ${FREETYPE_LIBRARIES}
    )
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
