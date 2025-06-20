#!/bin/bash

# --- Configuration ---
# User email for regular signup
USER_EMAIL="testuser@example.com"
# Admin email for bootstrap and admin access
ADMIN_EMAIL="your.admin@example.com"
# Base URL of your FIRM server (adjust port if different)
API_BASE="http://localhost:8092"

# --- Pre-requisites Check ---
# Check for 'jq'
if ! command -v jq &> /dev/null; then
    echo "❌ 'jq' is not installed. Please install it (e.g., sudo apt install jq)."
    exit 1
fi
# Check for 'curl'
if ! command -v curl &> /dev/null; then
    echo "❌ 'curl' is not installed. Please install it (e.g., sudo apt install curl)."
    exit 1
fi

echo "🚀 Starting FIRM Server Test Automation 🚀"
echo "API Base: $API_BASE"
echo ""

# --- STEP 1: Signup a regular user (passwordless) ---
echo "--- Step 1: Signing up a regular user ($USER_EMAIL) ---"
SIGNUP_RESPONSE=$(curl -s -X POST "$API_BASE/signup" \
  -H "Content-Type: application/json" \
  -d '{
      "email": "'"$USER_EMAIL"'"
      }')

echo "✅ Signup Response for $USER_EMAIL:"
echo "$SIGNUP_RESPONSE" | jq .

USER_FIRM_TOKEN=$(echo "$SIGNUP_RESPONSE" | jq -r '.token')

if [[ -z "$USER_FIRM_TOKEN" || "$USER_FIRM_TOKEN" == "null" ]]; then
  echo "❌ Failed to extract FIRM token for $USER_EMAIL. Exiting."
  exit 1
fi

echo "✅ Extracted FIRM Token for $USER_EMAIL: $USER_FIRM_TOKEN"
echo ""

# --- STEP 2: Simulate inbound verification for the regular user ---
echo "--- Step 2: Simulating inbound email verification for $USER_EMAIL ---"
# Note: The 'spf_pass' and 'dkim_pass' fields are not sent by the client,
# they are internal server-side checks. Removed from payload.
INBOUND_USER_RESPONSE=$(curl -s -X POST "$API_BASE/inbound" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$USER_EMAIL"'",
    "subject": "Verification '"$USER_FIRM_TOKEN"'",
    "body": "This is my verification email for '"$USER_EMAIL"'.",
    "headers": {
        "From": "'"$USER_EMAIL"'"
    }
  }')

echo "✅ Inbound Verification Response for $USER_EMAIL:"
echo "$INBOUND_USER_RESPONSE" | jq .

# Check if user verification was successful and a JWT was issued
USER_REFRESH_TOKEN=$(echo "$INBOUND_USER_RESPONSE" | jq -r '.refresh_token')
if [[ -z "$USER_REFRESH_TOKEN" || "$USER_REFRESH_TOKEN" == "null" ]]; then
  echo "❌ Failed to get refresh token for $USER_EMAIL. Verification might have failed. Exiting."
  exit 1
fi
echo "✅ Received User Refresh Token (first 20 chars): ${USER_REFRESH_TOKEN:0:20}..."
echo ""

# --- STEP 3: Bootstrap an admin email (localhost only) ---
echo "--- Step 3: Bootstrapping admin email ($ADMIN_EMAIL) ---"
BOOTSTRAP_RESPONSE=$(curl -s -X POST "$API_BASE/admin/bootstrap" \
  -H "Content-Type: application/json" \
  -d '{
      "email": "'"$ADMIN_EMAIL"'"
      }')

echo "✅ Admin Bootstrap Response:"
echo "$BOOTSTRAP_RESPONSE" | jq .

BOOTSTRAP_MESSAGE=$(echo "$BOOTSTRAP_RESPONSE" | jq -r '.message')
if [[ "$BOOTSTRAP_MESSAGE" != "Admin email added" && "$BOOTSTRAP_MESSAGE" != "null" ]]; then
  echo "❌ Admin bootstrap might have failed or returned unexpected message. Exiting."
  exit 1
fi
echo "✅ Admin email $ADMIN_EMAIL bootstrapped (or already exists)."
echo ""

# --- STEP 4: Signup for the admin email to get a fresh FIRM token ---
echo "--- Step 4: Signing up admin email ($ADMIN_EMAIL) to get FIRM token ---"
ADMIN_SIGNUP_RESPONSE=$(curl -s -X POST "$API_BASE/signup" \
  -H "Content-Type: application/json" \
  -d '{
      "email": "'"$ADMIN_EMAIL"'"
      }')

echo "✅ Admin Signup Response:"
echo "$ADMIN_SIGNUP_RESPONSE" | jq .

ADMIN_FIRM_TOKEN=$(echo "$ADMIN_SIGNUP_RESPONSE" | jq -r '.token')

if [[ -z "$ADMIN_FIRM_TOKEN" || "$ADMIN_FIRM_TOKEN" == "null" ]]; then
  echo "❌ Failed to extract FIRM token for $ADMIN_EMAIL. Exiting."
  exit 1
fi

echo "✅ Extracted FIRM Token for $ADMIN_EMAIL: $ADMIN_FIRM_TOKEN"
echo ""

# --- STEP 5: Simulating inbound verification for the admin email to get an ADMIN JWT ---
echo "--- Step 5: Simulating inbound email verification for admin ($ADMIN_EMAIL) ---"
ADMIN_INBOUND_RESPONSE=$(curl -s -X POST "$API_BASE/inbound" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$ADMIN_EMAIL"'",
    "subject": "Verification '"$ADMIN_FIRM_TOKEN"'",
    "body": "This is my admin verification email with token '"$ADMIN_FIRM_TOKEN"'.",
    "headers": {
        "From": "'"$ADMIN_EMAIL"'"
    }
  }')

echo "✅ Admin Inbound Verification Response:"
echo "$ADMIN_INBOUND_RESPONSE" | jq .

ADMIN_REFRESH_TOKEN=$(echo "$ADMIN_INBOUND_RESPONSE" | jq -r '.refresh_token')

if [[ -z "$ADMIN_REFRESH_TOKEN" || "$ADMIN_REFRESH_TOKEN" == "null" ]]; then
  echo "❌ Failed to get admin refresh token. Verification might have failed. Exiting."
  exit 1
fi

echo "✅ Received Admin Refresh Token (first 20 chars): ${ADMIN_REFRESH_TOKEN:0:20}..."
echo ""

# --- STEP 6: Test accessing a protected admin API endpoint with the ADMIN JWT ---
# IMPORTANT: The API endpoint for JSON data is now /admin/api/subnets, not /admin/subnets
echo "--- Step 6: Accessing protected admin API endpoint /admin/api/subnets ---"
PROTECTED_ADMIN_RESPONSE=$(curl -s -X GET "$API_BASE/admin/api/subnets" \
  -H "Authorization: Bearer $ADMIN_REFRESH_TOKEN")

echo "✅ Protected Admin API Endpoint Response (should be 200 OK and a JSON array):"
echo "$PROTECTED_ADMIN_RESPONSE" | jq .

# Check if the response indicates success (e.g., is a JSON array)
if echo "$PROTECTED_ADMIN_RESPONSE" | jq -e 'type == "array"' >/dev/null; then
  echo "✅ Successfully accessed /admin/api/subnets (received JSON array)."
else
  echo "❌ Failed to access /admin/api/subnets. Response was not a JSON array or indicated an error."
  echo "Full response: $PROTECTED_ADMIN_RESPONSE"
  exit 1
fi

echo ""
echo "🎉 All tests completed successfully! 🎉"
echo ""
echo "------------------------------------------------------------------------"
echo "🌐 To access the Admin Dashboard in your browser:"
echo "   1. Open: $API_BASE/admin/dashboard"
echo "   2. Open Browser Developer Tools (F12) -> Application/Storage -> Local Storage -> $API_BASE"
echo "   3. Add a new item:"
echo "      Key: admin_token"
echo "      Value: $ADMIN_REFRESH_TOKEN"
echo "   4. Refresh the dashboard page."
echo "------------------------------------------------------------------------"
echo ""

