# DNA Messenger - Qt GUI Build Configuration

cmake_minimum_required(VERSION 3.10)

# Find Qt5
find_package(Qt5 REQUIRED COMPONENTS Core Widgets Multimedia)

# Enable automatic MOC (Meta-Object Compiler)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# GUI source files
set(GUI_SOURCES
    main.cpp
    MainWindow.cpp
    MainWindow.h
    resources.qrc
)

# Create GUI executable
add_executable(dna_messenger_gui ${GUI_SOURCES})

# Link Qt libraries
target_link_libraries(dna_messenger_gui
    Qt5::Core
    Qt5::Widgets
    Qt5::Multimedia
    dna_lib
    ${PQ_LIBRARY}
)

# Include directories
target_include_directories(dna_messenger_gui PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${PQ_INCLUDE_DIR}
)

# Install GUI executable
if(WIN32)
    install(TARGETS dna_messenger_gui DESTINATION .)
else()
    install(TARGETS dna_messenger_gui DESTINATION bin)
endif()
