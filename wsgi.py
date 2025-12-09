# Lightweight wsgi loader to expose Flask app as `server` for Gunicorn.
# It loads your script file lib-final-v5-search-full-fixed.py and expects a Flask
# instance named `server` to be exported from it.

import importlib.util
from pathlib import Path

FILE_PATH = Path(__file__).parent / "lib-final-v5-search-full-fixed.py"

if not FILE_PATH.exists():
    raise RuntimeError(f"Expected application file at {FILE_PATH}")

spec = importlib.util.spec_from_file_location("app_module", str(FILE_PATH))
app_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_module)

# Expect the Flask app instance to be called `server`
try:
    server = getattr(app_module, "server")
except AttributeError:
    raise RuntimeError("The application module does not expose `server`. Please export your Flask app as `server`.")
