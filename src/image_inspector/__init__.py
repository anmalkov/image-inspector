"""image-inspector: pick and digest-pin official container base images."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("base-image-inspector")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+dev"
