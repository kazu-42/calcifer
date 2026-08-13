#!/bin/sh
set -eu

if [ "${1:-}" = "-c" ]; then
  [ "${2:-}" = 'cli_auth_credentials_store="file"' ]
  [ "${3:-}" = "-c" ]
  [ "${4:-}" = 'mcp_oauth_credentials_store="file"' ]
  shift 4
fi

case "${1:-}" in
  --version)
    printf '%s\n' 'codex-cli 0.144.4'
    ;;
  login)
    umask 077
    profile_id=$(basename "$(dirname "${CODEX_HOME:?}")")
    printf '{"auth_mode":"chatgpt","tokens":{"account_id":"scorecard-%s"}}\n' \
      "$profile_id" > "${CODEX_HOME}/auth.json"
    ;;
  app-server)
    IFS= read -r initialize
    case "$initialize" in
      *'"method":"initialize"'*) ;;
      *) exit 93 ;;
    esac
    printf '{"id":0,"result":{"userAgent":"calcifer/0.144.4 (scorecard)","platformFamily":"unix","platformOs":"linux","codexHome":"%s"}}\n' \
      "${CODEX_HOME:?}"
    IFS= read -r initialized || exit 0
    case "$initialized" in
      *'"method":"initialized"'*) ;;
      *) exit 92 ;;
    esac
    ;;
  *)
    exit 91
    ;;
esac
