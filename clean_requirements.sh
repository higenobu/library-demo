#!/usr/bin/env bash
# 簡易: requirements.txt から絶対パスやローカルフォルダ参照行を除去して一時ファイルに出す
IN=requirements.txt
OUT=/tmp/requirements.clean.txt
# この正規表現は先頭が "/" で始まる行や "file:" スキーム、ローカル相対パス "-e ." 等を除去
grep -v -E '^/|^file:|^-e |^\.\.?/' "$IN" > "$OUT"
echo "Wrote cleaned requirements to $OUT"
echo "Preview:"
sed -n '1,200p' "$OUT"
