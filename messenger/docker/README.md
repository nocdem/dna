# DNA Messenger Docker Images

## Windows Cross-Compilation Builder

This Docker image contains pre-built MinGW versions of common dependencies for cross-compiling Windows binaries from Linux.

### What's Included

- **Build Tools**: MinGW-w64, CMake, Git, Meson
- **Pre-built Windows Libraries**:
  - zlib
  - OpenSSL 3.0.12
  - libcurl 8.5.0
  - json-c
  - SQLite 3.44.2
  - msgpack-c
  - GLFW (for ImGui)
  - GLEW (for OpenGL)
  - FreeType 2.13.2

### What's Missing

Complex dependencies that are difficult to cross-compile:
- GLib (required by libnice)
- libnice (ICE/P2P)
- OpenDHT (DHT networking)
- GTK3 (file dialogs)

### Building the Image

```bash
# Build (takes 30-60 minutes)
docker build -f docker/Dockerfile.windows-builder -t dna-windows-builder .

# Test it
docker run --rm -it dna-windows-builder bash

# Push to Docker Hub (optional)
docker tag dna-windows-builder yourusername/dna-windows-builder:latest
docker push yourusername/dna-windows-builder:latest
```

### Using in GitLab CI

```yaml
build:windows-x64:
  stage: build
  image: yourusername/dna-windows-builder:latest
  script:
    - cmake . -DCMAKE_TOOLCHAIN_FILE=/build/mingw-toolchain.cmake
    - make
```

### Current Status

⚠️ **This image is incomplete** - it's missing critical dependencies (GLib, libnice, OpenDHT) that are very complex to cross-compile.

**Recommended Approach**:
1. Build Windows binaries natively on Windows using MSVC or MinGW
2. Use GitHub Actions with Windows runners
3. Use vcpkg for dependency management on Windows

This Dockerfile serves as a starting point but needs significant work to be production-ready.
