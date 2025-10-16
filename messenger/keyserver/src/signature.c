/*
 * Signature Verification - Dilithium3
 */

#include "signature.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

char* signature_build_canonical_json(json_object *payload) {
    // Create a copy without "sig" field
    json_object *canonical = json_object_new_object();

    json_object_object_foreach(payload, key, val) {
        if (strcmp(key, "sig") != 0) {
            json_object_object_add(canonical, key, json_object_get(val));
        }
    }

    const char *json_str = json_object_to_json_string_ext(canonical,
                                                          JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);

    json_object_put(canonical);

    return result;
}

int signature_verify(json_object *payload, const char *signature,
                    const char *public_key, const char *verify_path,
                    int timeout) {
    // Build canonical JSON (without sig field)
    char *canonical_json = signature_build_canonical_json(payload);
    if (!canonical_json) {
        return -2;
    }

    // Check if verify_json exists
    if (access(verify_path, X_OK) != 0) {
        LOG_ERROR("verify_json not found or not executable: %s", verify_path);
        free(canonical_json);
        return -2;
    }

    // Fork and execute verify_json
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERROR("fork() failed");
        free(canonical_json);
        return -2;
    }

    if (pid == 0) {
        // Child process
        execl(verify_path, verify_path, canonical_json, signature, public_key, NULL);
        _exit(1);  // exec failed
    }

    // Parent process - wait for child
    free(canonical_json);

    int status;
    pid_t result = waitpid(pid, &status, 0);

    if (result == -1) {
        LOG_ERROR("waitpid() failed");
        return -2;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            return 0;  // Valid signature
        } else {
            return -1;  // Invalid signature
        }
    }

    return -2;  // Error
}
