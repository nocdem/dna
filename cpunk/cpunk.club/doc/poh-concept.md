# CPUNK DNA Proof of Humanity Score Concept

## Overview

The Proof of Humanity (PoH) score provides a transparent measure of how likely a DNA registration belongs to a unique human user. Unlike traditional verification systems, the CPUNK implementation **does not require a minimum threshold** for registration, preserving user choice for anonymity while providing a community transparency metric.

## Core Components of PoH Score (0-100)

### 1. Behavioral Analysis (0-40 points)
- Mouse movement patterns (natural vs automated)
- Typing rhythm and variance
- Input error corrections
- Form interaction patterns
- Navigation and interaction timing

### 2. Social Verification (0-30 points)
- 10 points per verified OAuth platform
- Platforms: Twitter, GitHub, Google, etc.
- Account age and activity consideration
- Limited to public verification only (no private data access)

### 3. On-chain Activity (0-30 points)
- Wallet age
- Transaction history
- Transaction variety
- Interaction with known contracts
- Participation in community activities

## Key Principles

- **Optional Verification**: Users can register with any score (even 0)
- **Public Transparency**: PoH score visible to everyone viewing a DNA profile
- **User Choice**: Users decide their balance of anonymity vs. trustworthiness
- **Community Trust**: Other users can make informed decisions based on scores
- **Privacy Preserving**: No biometric data stored, only verification results
- **Upgrade Path**: Users can improve their score over time
- **Sybil Resistance**: Helps identify and discourage bot/duplicate accounts

## Use Cases

1. **Community Trust Signaling**
   - Users with high scores (80+) might be trusted for sensitive transactions
   - Community platforms might give additional privileges to high-score users
   - Messaging or trading might show the counterparty's PoH score

2. **User Discovery & Filtering**
   - DNA listings could be sorted or filtered by PoH score
   - Delegate selection could factor in PoH scores
   - Search results could prioritize higher-scoring DNAs

3. **Fraud Prevention**
   - Warning indicators for very low-scoring accounts
   - Flagging of suspicious registration patterns
   - Protection against mass bot registrations

4. **Optional Community Gating**
   - Individual services could set their own minimum score requirements
   - Special community features might require minimum scores
   - Tiered access based on verification level

## Implementation Considerations

- Calculate and store score during registration
- Display score prominently on user profiles
- Provide guidance for users to improve their score later if desired
- Include score in DNA API responses
- Adapt scoring weights based on effectiveness over time
- Consider score decay for inactive accounts

## Future Enhancements

- Reputation scoring from community interactions
- Integration with additional verification methods
- Score portability across platforms
- Enhanced on-chain analysis algorithms
- Community validation mechanisms

## Technical Requirements

- Client-side behavioral tracking
- Server-side score calculation and storage
- Integration with existing OAuth infrastructure
- On-chain analysis capabilities
- Score display in UI elements
- API extensions for score access