#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

case "${1:-}" in
  "" )
    exec python3 CryptoChessAssetManager.py launch
    ;;
  --status|status)
    exec python3 CryptoChessAssetManager.py status
    ;;
  --runtime-status)
    exec python3 CryptoChessAssetManager.py runtime-status
    ;;
  --restore-runtime-only)
    exec python3 CryptoChessAssetManager.py restore-runtime
    ;;
  --return-runtime)
    exec python3 CryptoChessAssetManager.py return-runtime
    ;;
  --verify-state)
    exec python3 CryptoChessAssetManager.py verify-state
    ;;
  --verify-assets)
    exec python3 CryptoChessAssetManager.py verify-assets
    ;;
  --verify-pqcassets)
    exec python3 CryptoChessAssetManager.py verify-pqcassets
    ;;
  --doctor)
    exec python3 CryptoChessAssetManager.py doctor
    ;;
  restore)
    shift
    exec python3 CryptoChessAssetManager.py restore "$@"
    ;;
  *)
    exec python3 CryptoChessAssetManager.py launch "$@"
    ;;
esac
