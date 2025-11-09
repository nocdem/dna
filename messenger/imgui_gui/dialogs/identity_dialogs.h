#ifndef IDENTITY_DIALOGS_H
#define IDENTITY_DIALOGS_H

#include "core/app_state.h"

// Forward declarations
class DNAMessengerApp;

namespace IdentityDialogs {

// Render identity selection dialog
void renderIdentitySelection(DNAMessengerApp* app);

// Create identity wizard steps
void renderCreateIdentityStep1(DNAMessengerApp* app);
void renderCreateIdentityStep2(DNAMessengerApp* app);
void renderCreateIdentityStep3(DNAMessengerApp* app);

// Restore identity wizard steps
void renderRestoreStep1_Name(DNAMessengerApp* app);
void renderRestoreStep2_Seed(DNAMessengerApp* app);

// Helper functions
void createIdentityWithSeed(DNAMessengerApp* app, const char* name, const char* mnemonic);
void restoreIdentityWithSeed(DNAMessengerApp* app, const char* name, const char* mnemonic);

} // namespace IdentityDialogs

#endif // IDENTITY_DIALOGS_H
