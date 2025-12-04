#ifndef WALLET_TRANSACTION_HISTORY_DIALOG_H
#define WALLET_TRANSACTION_HISTORY_DIALOG_H

#include "../core/app_state.h"

namespace WalletTransactionHistoryDialog {
    // Load transaction history from Cellframe RPC
    void load(AppState& state);

    // Render the transaction history dialog
    void render(AppState& state);
}

#endif // WALLET_TRANSACTION_HISTORY_DIALOG_H
