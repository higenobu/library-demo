-- If table `rent` exists and has column `rent_date`, set a default to CURRENT_DATE.
-- This script runs only on fresh database initialization (docker-entrypoint-initdb.d).
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'rent' AND column_name = 'rent_date'
  ) THEN
    EXECUTE 'ALTER TABLE rent ALTER COLUMN rent_date SET DEFAULT CURRENT_DATE';
  END IF;
END$$;
