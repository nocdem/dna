#ifndef WALLET_SCREEN_H
#define WALLET_SCREEN_H

#include "../core/app_state.h"
#include <string>

namespace WalletScreen {
    // Load wallet from Cellframe node
    void loadWallet(AppState& state);
    
    // Preload balances for all wallets (used during startup and periodic refresh)
    void preloadAllBalances(AppState& state);

    // Format balance with smart decimals
    std::string formatBalance(const std::string& coins);

    // Render the main wallet view
    void render(AppState& state);
}

#endif // WALLET_SCREEN_H
