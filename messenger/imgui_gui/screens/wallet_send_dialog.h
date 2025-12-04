#ifndef WALLET_SEND_DIALOG_H
#define WALLET_SEND_DIALOG_H

#include "../core/app_state.h"

namespace WalletSendDialog {
    // Render the send dialog and handle transaction building/submission
    void render(AppState& state);

    // Internal helper: Build and submit transaction to blockchain
    void buildAndSendTransaction(AppState& state);
}

#endif // WALLET_SEND_DIALOG_H
