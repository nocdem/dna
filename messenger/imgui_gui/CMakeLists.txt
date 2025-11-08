cmake_minimum_required(VERSION 3.10)

# ImGui GUI for DNA Messenger
project(dna_messenger_imgui CXX)

set(CMAKE_CXX_STANDARD 17)

# Enable wide character support for emoji (U+10000+)
add_definitions(-DIMGUI_USE_WCHAR32)
# Enable FreeType for colored emoji
add_definitions(-DIMGUI_ENABLE_FREETYPE)

# Find required packages
find_package(OpenGL REQUIRED)
find_package(glfw3 REQUIRED)
find_package(Freetype REQUIRED)

# ImGui source files
set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    ${IMGUI_DIR}/misc/freetype/imgui_freetype.cpp
)

# Main application
add_executable(dna_messenger_imgui
    main.cpp
    settings_manager.cpp
    ${IMGUI_SOURCES}
)

target_include_directories(dna_messenger_imgui PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMGUI_DIR}/misc/freetype
    ${FREETYPE_INCLUDE_DIRS}
)

target_link_libraries(dna_messenger_imgui PRIVATE
    OpenGL::GL
    glfw
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(dna_messenger_imgui PRIVATE
        opengl32
        gdi32
        ${FREETYPE_LIBRARIES}
        harfbuzz
        png
        z
        bz2
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
