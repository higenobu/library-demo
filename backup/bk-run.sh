#!/usr/bin/env bash

set -euo pipefail

echo "=== run.sh: starting ==="
# 例: 仮想環境を作る／アクティベートではなく直接実行するケース
# 実行したいコマンドに合わせて書き換えてください
# 例: Flask アプリを起動する場合
# export FLASK_APP=app.py
# flask run --host=0.0.0.0 --port=5000

# 既存のプロジェクト向けのデフォルト（run_doctor.py / run.sh の例）
if [ -f "./run_doctor.py" ]; then
  python3 run_doctor.py
else
  # デフォルトとして簡易 HTTP server を立てる（デバッグ用）
  echo "run_doctor.py が見つかりません。代わりに簡易サーバ起動（ポート5000）。"
  python3 -m http.server 5000
fi
