# cpunk-wallet-gui - Standalone CF20 Wallet Build Configuration

cmake_minimum_required(VERSION 3.10)

# Find Qt5
find_package(Qt5 REQUIRED COMPONENTS Core Widgets)

# Find CURL (required for Cellframe RPC)
find_package(CURL REQUIRED)

# Enable automatic MOC (Meta-Object Compiler)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Wallet GUI source files
set(WALLET_GUI_SOURCES
    main_wallet.cpp
    WalletMainWindow.cpp
    WalletMainWindow.h
    SendTokensDialog.cpp
    SendTokensDialog.h
    TransactionHistoryWidget.cpp
    TransactionHistoryWidget.h
    cpunk_themes.h
    ../wallet.c
    ../cellframe_rpc.c
    ../cellframe_addr.c
    ../base58.c
)

# Create wallet GUI executable
add_executable(cpunk-wallet-gui ${WALLET_GUI_SOURCES})

# Link Qt libraries
target_link_libraries(cpunk-wallet-gui
    Qt5::Core
    Qt5::Widgets
    cellframe_minimal
    cellframe_dilithium
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    ${JSONC_LIBRARIES}
    m
)

# Include directories
target_include_directories(cpunk-wallet-gui PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${PQ_INCLUDE_DIR}
)

# Install wallet GUI executable
if(WIN32)
    install(TARGETS cpunk-wallet-gui DESTINATION .)
else()
    install(TARGETS cpunk-wallet-gui DESTINATION bin)
endif()
