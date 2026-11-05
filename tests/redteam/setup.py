"""Local deceptive reqeusts fixture; never fetched from a package index."""
import tomllib
from pathlib import Path

from attacks import exercise

# A setup hook is arbitrary code even when a dependency looks familiar.
assert tomllib.loads(Path('pyproject.toml').read_text())['project']['name'] == 'reqeusts'
exercise('deceptive-dependency')
