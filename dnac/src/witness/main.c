/**
 * @file main.c
 * @brief DNAC Witness Server entry point
 *
 * The witness server provides double-spend prevention for DNAC transactions
 * using BFT (Byzantine Fault Tolerant) consensus over TCP.
 *
 * Usage: dnac-witness [options]
 *   -d <dir>    Data directory (default: ~/.dna)
 *   -p <port>   TCP port (default: 4200)
 *   -a <addr>   My address for BFT roster (IP:port)
 *   -r <roster> Initial roster file (optional)
 *   -h          Show help
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

/* External BFT main function */
extern int bft_witness_main(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    /* BFT consensus is the only mode */
    return bft_witness_main(argc, argv);
}
