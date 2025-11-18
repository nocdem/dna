# DNA Messenger Docker Images

## Windows Cross-Compilation Builder

This Docker image contains pre-built MinGW versions of ALL dependencies needed to cross-compile DNA Messenger for Windows from Linux.

### What's Included

- **Build Tools**: MinGW-w64, CMake, Git, Meson, Ninja
- **All Windows Libraries** (statically built):
  - **Core**: zlib, OpenSSL 3.0.12, libcurl 8.5.0, json-c, SQLite 3.44.2
  - **DHT/P2P**: GLib 2.78.3, libnice, OpenDHT 3.x, msgpack-c
  - **Crypto**: GnuTLS 3.8.2, nettle, argon2, jsoncpp
  - **ImGui**: GLFW, GLEW, FreeType 2.13.2
  - **Supporting**: libffi, pcre2, libiconv, gettext, GMP

### Building the Image

```bash
# Build (takes 1-2 hours on first build)
docker build -f docker/Dockerfile.windows-builder -t dna-windows-builder .

# Test it
docker run --rm -it dna-windows-builder bash

# Push to Docker Hub for CI use
docker tag dna-windows-builder yourname/dna-windows-builder:latest
docker push yourname/dna-windows-builder:latest
```

### Using Locally

```bash
# Run container with your source mounted
docker run --rm -v $(pwd):/workspace -w /workspace dna-windows-builder bash

# Inside container:
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=/build/mingw-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Windows .exe will be in build/imgui_gui/dna_messenger_imgui.exe
```

### Using in GitLab CI

```yaml
build:windows-x64:
  stage: build
  image: yourname/dna-windows-builder:latest
  script:
    - mkdir build && cd build
    - cmake .. -DCMAKE_TOOLCHAIN_FILE=/build/mingw-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
    - make -j$(nproc)
  artifacts:
    paths:
      - build/imgui_gui/dna_messenger_imgui.exe
```

### What Makes This Work

- All libraries compiled with static linking (`-static -static-libgcc -static-libstdc++`)
- CMake toolchain file pre-configured at `/build/mingw-toolchain.cmake`
- Meson cross-file for GLib/libnice at `/build/mingw-cross.txt`
- All libraries installed to `/usr/x86_64-w64-mingw32` (MinGW sysroot)
- PKG_CONFIG_PATH properly configured

### File Dialogs on Windows

Windows uses native file dialogs (`nfd_win.cpp`) - no GTK3 needed!
