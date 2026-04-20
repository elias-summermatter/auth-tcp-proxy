import os
import sys

from app import create_app, load_config

_config_path = os.environ.get("CONFIG", "/app/config.yaml")
if not os.path.exists(_config_path):
    print(f"Config not found: {_config_path}", file=sys.stderr)
    sys.exit(1)

app = create_app(load_config(_config_path))
