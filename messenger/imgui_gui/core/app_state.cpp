#include "app_state.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

AppState::AppState() {
    current_view = VIEW_CONTACTS;
    selected_contact = -1;
    prev_selected_contact = -1;
    selected_group = -1;
    is_viewing_group = false;
    should_focus_input = false;
    input_cursor_pos = -1;
    show_wallet = false;
    show_identity_selection = true;
    is_first_frame = true;
    loading_start_time = 0.0f;
    show_operation_spinner = false;
    identity_loaded = false;
    identities_scanned = false;
    selected_identity_idx = -1;
    create_identity_step = STEP_NAME;
    restore_identity_step = RESTORE_STEP_SEED;
    seed_confirmed = false;
    seed_copied = false;
    seed_copied_timer = 0.0f;
    show_emoji_picker = false;
    emoji_picker_pos = ImVec2(0, 0);
    show_add_contact_dialog = false;
    add_contact_lookup_in_progress = false;
    add_contact_last_input_time = 0.0f;
    add_contact_profile_loaded = false;
    add_contact_profile_loading = false;
    add_contact_profile = nullptr;
    new_messages_received = false;
    memset(new_identity_name, 0, sizeof(new_identity_name));
    memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
    memset(message_input, 0, sizeof(message_input));
    memset(add_contact_input, 0, sizeof(add_contact_input));
    messenger_ctx = nullptr;

    // Initialize wallet state
    wallet_loaded = false;
    wallet_loading = false;
    wallet_list = nullptr;
    current_wallet_index = -1;

    // Initialize receive dialog state
    show_receive_dialog = false;
    memset(wallet_address, 0, sizeof(wallet_address));
    address_copied = false;
    address_copied_timer = 0.0f;

    // Initialize send dialog state
    show_send_dialog = false;
    memset(send_recipient, 0, sizeof(send_recipient));
    strcpy(send_amount, "0.001");  // Default amount
    strcpy(send_fee, "0.01");      // Default fee

    // Initialize transaction history dialog state
    show_transaction_history = false;
    transaction_history_loading = false;

    // Initialize message wall dialog state
    show_message_wall = false;
    wall_is_own = false;
    wall_loading = false;
    memset(wall_message_input, 0, sizeof(wall_message_input));

    // Initialize profile editor dialog state
    show_profile_editor = false;
    profile_loading = false;
    profile_cached = false;
    memset(profile_backbone, 0, sizeof(profile_backbone));
    memset(profile_kelvpn, 0, sizeof(profile_kelvpn));
    memset(profile_subzero, 0, sizeof(profile_subzero));
    memset(profile_millixt, 0, sizeof(profile_millixt));
    memset(profile_testnet, 0, sizeof(profile_testnet));
    memset(profile_btc, 0, sizeof(profile_btc));
    memset(profile_eth, 0, sizeof(profile_eth));
    memset(profile_sol, 0, sizeof(profile_sol));
    memset(profile_ltc, 0, sizeof(profile_ltc));
    memset(profile_doge, 0, sizeof(profile_doge));
    memset(profile_telegram, 0, sizeof(profile_telegram));
    memset(profile_twitter, 0, sizeof(profile_twitter));
    memset(profile_github, 0, sizeof(profile_github));
    memset(profile_discord, 0, sizeof(profile_discord));
    memset(profile_website, 0, sizeof(profile_website));
    memset(profile_pic_cid, 0, sizeof(profile_pic_cid));
    memset(profile_bio, 0, sizeof(profile_bio));
    memset(profile_avatar_path, 0, sizeof(profile_avatar_path));
    profile_avatar_loaded = false;
    profile_avatar_preview_loaded = false;
    profile_avatar_marked_for_removal = false;

    // Initialize contact profile viewer state
    show_contact_profile = false;
    viewed_profile_avatar_loaded = false;
    viewed_profile_loading = false;
    memset(viewed_profile_backbone, 0, sizeof(viewed_profile_backbone));
    memset(viewed_profile_kelvpn, 0, sizeof(viewed_profile_kelvpn));
    memset(viewed_profile_subzero, 0, sizeof(viewed_profile_subzero));
    memset(viewed_profile_testnet, 0, sizeof(viewed_profile_testnet));
    memset(viewed_profile_btc, 0, sizeof(viewed_profile_btc));
    memset(viewed_profile_eth, 0, sizeof(viewed_profile_eth));
    memset(viewed_profile_sol, 0, sizeof(viewed_profile_sol));
    memset(viewed_profile_telegram, 0, sizeof(viewed_profile_telegram));
    memset(viewed_profile_twitter, 0, sizeof(viewed_profile_twitter));
    memset(viewed_profile_github, 0, sizeof(viewed_profile_github));
    memset(viewed_profile_bio, 0, sizeof(viewed_profile_bio));

    // Initialize register name dialog state
    show_register_name = false;
    register_name_available = false;
    register_name_checking = false;
    register_name_last_input_time = 0.0f;
    register_name_last_checked_input = "";
    memset(register_name_input, 0, sizeof(register_name_input));

    // Initialize create group dialog state (Phase 1.3)
    show_create_group_dialog = false;
    create_group_in_progress = false;
    memset(create_group_name_input, 0, sizeof(create_group_name_input));

    // Initialize group invitation dialog state (Phase 6.1)
    show_group_invitation_dialog = false;
    selected_invitation_index = -1;
    invitation_action_in_progress = false;

    // Initialize feed state (Phase 7: Public Feed)
    selected_feed_channel = -1;
    feed_loading = false;
    memset(feed_post_input, 0, sizeof(feed_post_input));
    show_create_channel_dialog = false;
    create_channel_in_progress = false;
    memset(create_channel_name, 0, sizeof(create_channel_name));
    memset(create_channel_desc, 0, sizeof(create_channel_desc));
}
