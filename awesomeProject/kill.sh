#!/usr/bin/env bash
set -Eeuo pipefail

# 先用 pid 文件优雅停止
if compgen -G "pids/*.pid" >/dev/null; then
  for f in pids/*.pid; do
    pid=$(cat "$f" || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" || true
    fi
  done
  sleep 2
fi

# 兜底：仍残留则强杀
pkill -KILL -f '^\./main\b' || true

# （可选）清锁文件——仅在确认没有 main 存活之后
if ! pgrep -af '^\./main\b' >/dev/null; then
  while IFS= read -r d || [[ -n "$d" ]]; do
    d="${d%$'\r'}"
    [[ -z "$d" || "$d" =~ ^[[:space:]]*# ]] && continue
    rm -f "$d/LOCK" "$d/LOCKFILE" "$d/.lock" 2>/dev/null || true
    rm -f "$d"/*.db-wal "$d"/*.db-shm 2>/dev/null || true
  done < filesks1.txt
fi

echo "已停止。"
