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
    WalletDialog.cpp
    WalletDialog.h
    ../wallet.c
    ../cellframe_rpc.c
    ../cellframe_addr.c
    ../base58.c
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
    ${PQ_LIBRARY}
    ${JSONC_LIBRARIES}
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
