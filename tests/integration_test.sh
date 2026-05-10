#!/bin/bash
set -e

# Integration test for DeviceEncryptionYubiKey
# This script runs a full cycle: Setup -> Get Nonce -> Unwrap -> Wrap -> Unlock

SERVER_BIN="./deyk-server/target/debug/deyk-server"
CLIENT_BIN="./deyk-client/target/debug/deyk-client"
SERVER_CONFIG="test_server_config.json"
CLIENT_CONFIG="test_client_config.json"

# Cleanup before starting
rm -f $SERVER_CONFIG $CLIENT_CONFIG

# 1. Setup Mock YubiKey
MOCK_ECDH_PRIV="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
MOCK_SIGN_PRIV="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
export DEYK_MOCK_ECDH_PRIV=$MOCK_ECDH_PRIV
export DEYK_MOCK_SIGN_PRIV=$MOCK_SIGN_PRIV

# Calculate MOCK_ECDH_PUB
MOCK_ECDH_PUB="04d8cd12ea5c67f2f8a00c1124893edcfa6754c4d6cede6be13bdf2295c810a97fa5a89d2d2a360c0ca9a4d6c7c9ed4b28d3e199d6627f2e696d689c310a5b0f48"
MOCK_SIGN_PUB="047021319717d54407519196b0523e387c6999120689b936d354b23267756f1784570086382092f6ed1b945f096d2a7042f4949a26569a47ca5439c05c0649774a"

echo "--- Phase A: Server Setup ---"
# Extract JSON from output (in case there's "Generating server keypair...")
SETUP_RAW=$($SERVER_BIN setup --config $SERVER_CONFIG --set-yubikey-ecdh-pub $MOCK_ECDH_PUB --set-yubikey-sign-pub $MOCK_SIGN_PUB 2>&1)
SETUP_OUT=$(echo "$SETUP_RAW" | sed -n '/{/,$p')
echo "$SETUP_OUT" | jq .

C_YK=$(echo "$SETUP_OUT" | jq -r .c_yk)
K_E_PUB=$(echo "$SETUP_OUT" | jq -r .k_e_pub)
K_S_PUB=$(echo "$SETUP_OUT" | jq -r .server_pub_key)
EXPECTED_DEK=$(echo "$SETUP_OUT" | jq -r .plaintext_dek)

if [ "$C_YK" == "null" ] || [ "$K_E_PUB" == "null" ]; then
    echo "Error: Server setup failed to return c_yk or k_e_pub"
    echo "$SETUP_RAW"
    exit 1
fi

echo "--- Phase B: Client Unwrap ---"
# Client output is not JSON, it prints "DEK unwrapped successfully!" then the hex on the next line
UNWRAP_OUT=$($CLIENT_BIN unwrap --c-yk $C_YK --k-e-pub $K_E_PUB --set-k-s-pub $K_S_PUB --config $CLIENT_CONFIG 2>&1 | grep -v "Mock")
echo "$UNWRAP_OUT"
DEK=$(echo "$UNWRAP_OUT" | tail -n 1)

if [ "$DEK" != "$EXPECTED_DEK" ]; then
    echo "Error: Unwrapped DEK does not match expected DEK!"
    echo "Expected: $EXPECTED_DEK"
    echo "Got:      $DEK"
    exit 1
fi

echo "--- Phase C: Client Wrap ---"
# 1. Get Nonce from server
NONCE_RAW=$($SERVER_BIN get-nonce --config $SERVER_CONFIG 2>&1)
NONCE_OUT=$(echo "$NONCE_RAW" | sed -n '/{/,$p')
SERVER_NONCE=$(echo "$NONCE_OUT" | jq -r .server_nonce)
echo "Server Nonce: $SERVER_NONCE"

# 2. Wrap for transport
WRAP_OUT=$($CLIENT_BIN wrap --dek $DEK --nonce $SERVER_NONCE --config $CLIENT_CONFIG 2>&1 | grep -v "Mock")
echo "$WRAP_OUT"
PAYLOAD=$(echo "$WRAP_OUT" | grep "Payload Hex:" | cut -d ' ' -f 3)
CLIENT_NONCE=$(echo "$WRAP_OUT" | grep "Client Nonce Hex:" | cut -d ' ' -f 4)

echo "--- Phase D: Server Unlock ---"
UNLOCK_RAW=$($SERVER_BIN unlock --config $SERVER_CONFIG --payload $PAYLOAD --client-nonce $CLIENT_NONCE 2>&1)
UNLOCK_OUT=$(echo "$UNLOCK_RAW" | sed -n '/{/,$p')
echo "$UNLOCK_OUT" | jq .

FINAL_DEK=$(echo "$UNLOCK_OUT" | jq -r .dek)

if [ "$FINAL_DEK" != "$EXPECTED_DEK" ]; then
    echo "Error: Final DEK does not match expected DEK!"
    echo "Expected: $EXPECTED_DEK"
    echo "Got:      $FINAL_DEK"
    exit 1
fi

# Verify nonce is cleared
echo "--- Verifying Nonce Clearing ---"
set +e
RE_UNLOCK_OUT=$($SERVER_BIN unlock --config $SERVER_CONFIG --payload $PAYLOAD --client-nonce $CLIENT_NONCE 2>&1)
set -e
if [[ "$RE_UNLOCK_OUT" == *"No active nonce found"* ]]; then
    echo "Success: Nonce was correctly cleared after first use."
else
    echo "Error: Server allowed re-use of nonce or failed with unexpected error."
    echo "$RE_UNLOCK_OUT"
    exit 1
fi

echo "INTEGRATION TEST PASSED!"
rm -f $SERVER_CONFIG $CLIENT_CONFIG
