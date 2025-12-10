```markdown
# dash-demo: Docker / docker-compose 環境

このリポジトリのアプリを Docker で立ち上げるための設定を追加しました。

起動手順（開発向け）
1. ルートにあるファイルをコミットしていない場合は保存してください。
2. ターミナルでルートディレクトリに移動して、次を実行します:
   docker compose up --build

3. ブラウザで http://localhost:8050 を開きます。

注意点
- 初回起動時のみ `docker/db/init/*.sql` 内の SQL が Postgres に適用されます。既に DB データがある場合は適用されません。
- production 用には FLASK_SECRET を安全な値にして、volumes のマウントを外し、機密情報は環境変数/シークレットで管理してください。

もし既存の DB に対して rent_date のデフォルトを付与したい場合（すでにデータがある場合）、以下を手動で実行してください（ホストから psql 実行）:
  docker compose exec -T db psql -U matsuo -d emr_sample -c "ALTER TABLE rent ALTER COLUMN rent_date SET DEFAULT CURRENT_DATE;"

バックアップを忘れずに。
```
再発防止と改善提案（短く・優先度順）

コメントで理由を残す

「なぜコメントアウトしたか」「戻すにはどのファイルのどの関数を復活させるか」をソース内に明記しておくと、将来同じミスを防げます。
単一ライター原則を守る（既に意識済みならそのままでOK）

複数のコールバックが同じ出力を更新しないよう、どの callback がどの出力を責任持って書くかを設計書きしておく。今回のように「テーブル更新は load_rents_table のみ」が分かると安全です。
自動テスト or 手順メモを残す

「ログイン → /debug/my_rents が非空 → テーブル表示」などの手順を README に追記するか、簡単な統合テスト（HTTPで /debug/my_rents と /_dash-update-component の存在確認）を作ると安心です。
ログを残す（既に入れているログで十分）

load_rents_table の呼び出しログや get_rented_books_for_user の行数ログは有効でした。削除せずに残しておくと障害対応が速くなります。
開発運用ルール（チームでなら）

コールバックの変更は PR レビューで「出力一覧（_dash-dependencies）」を確認するルールを入れると良いです。特に複数出力のときは差し替えミスが起きやすいです。
