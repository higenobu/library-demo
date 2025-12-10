# Python 3.12 slim をベースにアプリを動かす Dockerfile
FROM python:3.12-slim

# 必要な OS パッケージ（ビルドや PostgreSQL client 用）
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libpq-dev netcat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 依存を先にコピーしてインストール（ビルドキャッシュ活用）
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# アプリコードをコピー
COPY . /app

# wait-for-it スクリプト配置（docker/wait-for-it.sh をコピー）
COPY docker/wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

# expose Dash default port
EXPOSE 8050

# 環境変数のデフォルト（必要に応じて docker-compose.yml で上書き）
ENV FLASK_ENV=production
ENV PORT=8050

# デフォルトコマンド: DB が立ち上がるまで待ってからアプリを起動
# NOTE: DATABASE_URL は docker-compose.yml で渡します
CMD ["/bin/sh", "-c", "/wait-for-it.sh db:5432 --timeout=60 --strict -- python lib-final-v5-search-full-fixed.py --run"]
