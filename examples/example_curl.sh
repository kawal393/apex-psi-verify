# example_curl.sh
# ===============
# Start the verify API first:
#   python -m apex_psi_verify --port 5000
#

# 1. Health
curl -s http://127.0.0.1:5000/health | python -m json.tool

# 2. Create a seal
SEAL=$(curl -s -X POST http://127.0.0.1:5000/seal \
  -H "Content-Type: application/json" \
  -d '{"content": "The price of bread is 1.20 EUR on 2026-07-16."}')
echo "$SEAL" | python -m json.tool

# 3. Extract seal_id
SEAL_ID=$(echo "$SEAL" | python -c "import json,sys; print(json.load(sys.stdin)['seal_id'])")

# 4. Verify
curl -s -X POST http://127.0.0.1:5000/verify \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"The price of bread is 1.20 EUR on 2026-07-16.\", \"seal_id\": \"$SEAL_ID\"}" \
  | python -m json.tool

# 5. Tamper test (must return verified=false)
curl -s -X POST http://127.0.0.1:5000/verify \
  -H "Content-Type: application/json" \
  -d "{\"content\": \"The price of bread is 0.01 EUR on 2026-07-16.\", \"seal_id\": \"$SEAL_ID\"}" \
  | python -m json.tool
