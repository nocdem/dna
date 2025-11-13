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
    ../blockchain_rpc.c
    ../blockchain_addr.c
    ../base58.c
)

# Create wallet GUI executable
add_executable(cpunk-wallet-gui ${WALLET_GUI_SOURCES})

# For static CURL on Windows, define CURL_STATICLIB
if(WIN32)
    target_compile_definitions(cpunk-wallet-gui PRIVATE CURL_STATICLIB)
endif()

# Link Qt libraries
target_link_libraries(cpunk-wallet-gui
    Qt5::Core
    Qt5::Widgets
    cellframe_minimal
    cellframe_dilithium
    ${JSONC_LIBRARIES}
)

# Link CURL and OpenSSL (order matters for static linking)
if(WIN32)
    # For Windows static builds, CURL needs OpenSSL dependencies
    if(TARGET CURL::libcurl)
        target_link_libraries(cpunk-wallet-gui CURL::libcurl)
    else()
        target_link_libraries(cpunk-wallet-gui ${CURL_LIBRARIES})
    endif()

    # Static CURL requires OpenSSL and zlib
    target_link_libraries(cpunk-wallet-gui
        OpenSSL::SSL
        OpenSSL::Crypto
        z  # zlib
    )

    # CURL dependencies (static linking requires all)
    target_link_libraries(cpunk-wallet-gui
        nghttp2     # HTTP/2 support
        ssh2        # SSH/SFTP support
        psl         # Public Suffix List
        idn2        # Internationalized Domain Names
        unistring   # Unicode string library (required by psl and idn2)
        iconv       # Character encoding conversion (required by unistring)
        zstd        # ZSTD compression
        brotlidec   # Brotli decompression
        brotlicommon # Brotli common functions
    )

    # Windows system libraries (required by OpenSSL, CURL, and Qt)
    target_link_libraries(cpunk-wallet-gui
        bcrypt      # Windows Cryptography API
        ws2_32      # Windows Sockets
        crypt32     # Cryptography
        secur32     # Security functions (SSPI)
        wldap32     # LDAP support
        normaliz    # Internationalization (CURL)
    )
else()
    # Linux: simple CURL, OpenSSL, and math library linking
    target_link_libraries(cpunk-wallet-gui ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} m)
endif()

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
