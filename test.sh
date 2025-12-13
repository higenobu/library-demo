# start db
docker compose up -d db

# create test DB
docker compose exec db psql -U postgres -c "CREATE DATABASE library_test OWNER postgres;"

# prepare schema inside web container by calling app.ensure_tables()
docker compose run --rm --entrypoint python web -c "from app import ensure_tables; ensure_tables()"

# run pytest against test DB
docker compose run --rm -e DATABASE_URL='postgresql://postgres:postgres@db:5432/library_test' web pytest -q
