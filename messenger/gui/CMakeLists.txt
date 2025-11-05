# DNA Messenger - Qt GUI Build Configuration

cmake_minimum_required(VERSION 3.10)

# Find Qt5
find_package(Qt5 REQUIRED COMPONENTS Core Widgets Multimedia)

# Find CURL (required for Cellframe RPC in wallet)
find_package(CURL REQUIRED)

# Enable automatic MOC (Meta-Object Compiler)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# GUI source files
set(GUI_SOURCES
    main.cpp
    MainWindow.cpp
    MainWindow.h
    IdentitySelectionDialog.cpp
    IdentitySelectionDialog.h
    CreateIdentityDialog.cpp
    CreateIdentityDialog.h
    RestoreIdentityDialog.cpp
    RestoreIdentityDialog.h
    SeedPhraseWidget.cpp
    SeedPhraseWidget.h
    WalletDialog.cpp
    WalletDialog.h
    SendTokensDialog.cpp
    SendTokensDialog.h
    ReceiveDialog.cpp
    ReceiveDialog.h
    TransactionHistoryDialog.cpp
    TransactionHistoryDialog.h
    ThemeManager.cpp
    ThemeManager.h
    MigrateIdentityDialog.cpp
    MigrateIdentityDialog.h
    RegisterDNANameDialog.cpp
    RegisterDNANameDialog.h
    ProfileEditorDialog.cpp
    ProfileEditorDialog.h
    MessageWallDialog.cpp
    MessageWallDialog.h
    ../wallet.c
    ../cellframe_rpc.c
    ../cellframe_addr.c
    ../base58.c
    ../bip39.c
    ../bip39_pbkdf2.c
    ../seed_derivation.c
    ../keygen.c
    resources.qrc
)

# Create GUI executable
add_executable(dna_messenger_gui ${GUI_SOURCES})

# For static CURL on Windows, define CURL_STATICLIB
if(WIN32)
    target_compile_definitions(dna_messenger_gui PRIVATE CURL_STATICLIB)
endif()

# Link Qt libraries
target_link_libraries(dna_messenger_gui
    Qt5::Core
    Qt5::Widgets
    Qt5::Multimedia
    dna_lib
    cellframe_minimal
    cellframe_dilithium
    dsa
    ${PQ_LIBRARY}
    ${JSONC_LIBRARIES}
    ${SQLite3_LIBRARIES}
)

# Link CURL and OpenSSL (order matters for static linking)
if(WIN32)
    # For Windows static builds, CURL needs OpenSSL dependencies
    if(TARGET CURL::libcurl)
        target_link_libraries(dna_messenger_gui CURL::libcurl)
    else()
        target_link_libraries(dna_messenger_gui ${CURL_LIBRARIES})
    endif()

    # Static CURL requires OpenSSL and zlib
    target_link_libraries(dna_messenger_gui
        OpenSSL::SSL
        OpenSSL::Crypto
        z  # zlib
    )

    # CURL dependencies (static linking requires all)
    target_link_libraries(dna_messenger_gui
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
else()
    # Linux: simple CURL and OpenSSL linking
    target_link_libraries(dna_messenger_gui ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} m)
endif()

# Add PostgreSQL internal libraries and Windows system libraries for static linking
if(WIN32)
    # PostgreSQL internal libraries (required for static linking)
    find_library(PGCOMMON_LIBRARY NAMES pgcommon libpgcommon PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
    find_library(PGPORT_LIBRARY NAMES pgport libpgport PATHS ${CMAKE_FIND_ROOT_PATH}/lib)

    if(PGCOMMON_LIBRARY)
        target_link_libraries(dna_messenger_gui ${PGCOMMON_LIBRARY})
    endif()

    if(PGPORT_LIBRARY)
        target_link_libraries(dna_messenger_gui ${PGPORT_LIBRARY})
    endif()

    # Windows system libraries required by PostgreSQL, CURL, and OpenSSL (static linking)
    target_link_libraries(dna_messenger_gui
        bcrypt       # Windows Cryptography API
        secur32      # Security functions (SSPI, credentials)
        ws2_32       # Windows Sockets 2
        crypt32      # Cryptography functions
        wldap32      # LDAP support (PostgreSQL + CURL)
        normaliz     # Internationalization (CURL)
    )

    # Phase 9.1: P2P/DHT support - explicit linkage needed for Windows static builds
    # Use linker groups and whole-archive to handle circular dependencies and force gnutls stubs
    target_link_libraries(dna_messenger_gui
        -Wl,--start-group
        p2p_transport  # P2P transport layer (depends on DHT)
        -Wl,--whole-archive
        dht_lib        # DHT library with gnutls stubs (force all symbols including stubs)
        -Wl,--no-whole-archive
        -Wl,--end-group
    )
endif()

# Include directories
target_include_directories(dna_messenger_gui PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${PQ_INCLUDE_DIR}
)

# Add json-c include directories if found
if(JSONC_INCLUDE_DIRS)
    target_include_directories(dna_messenger_gui PRIVATE ${JSONC_INCLUDE_DIRS})
endif()

# Install GUI executable
if(WIN32)
    install(TARGETS dna_messenger_gui DESTINATION .)
else()
    install(TARGETS dna_messenger_gui DESTINATION bin)
endif()
