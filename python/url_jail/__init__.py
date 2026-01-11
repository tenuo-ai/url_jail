# url_jail Python package
# Re-exports from Rust extension module plus Python adapters

from .url_jail import *

# Make adapters accessible as url_jail.adapters
from . import adapters

__doc__ = url_jail.__doc__
if hasattr(url_jail, "__all__"):
    __all__ = url_jail.__all__ + ["adapters"]
