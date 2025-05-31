# CPUNK Platform TODO List

## High Priority

### 1. Fix wallet balance loading issue
- **Problem**: Balance shows 0 mCELL preventing delegation
- **Root Cause**: `availableBalance` initialized to 0 but never updated
- **Solution**: Implement proper balance loading from dashboard API
- **Status**: Pending

### 2. Create validator components (wallet + 2 certificates)
- **Task**: Implement createValidatorComponents() function
- **Components**:
  - Validator wallet: `<dna>-<uuid>`
  - Node certificate: `<dna>-<uuid>-node`
  - Delegation certificate: `<dna>-<uuid>-delegation`
- **Status**: Pending

### 3. Update delegation to use CreateOrderValidator API
- **Task**: Replace CreateOrderStaker with CreateOrderValidator
- **Parameters**: Use validator node address instead of regular wallet
- **Status**: Pending

### 4. Implement srv_stake delegate call with order hash
- **Task**: Execute delegation using srv_stake command
- **Command**: `srv_stake delegate -cert <cert_name> -order <order_hash> -value <amount>`
- **Status**: Pending

## Medium Priority

### 5. Update success message to show validator components
- **Task**: Display created validator wallet name, certificates, and node address
- **Format**: Clear message showing all created components
- **Status**: Pending

## Notes
- Work gradually after reverting to stable version
- Test each change thoroughly before moving to next
- Keep implementations simple