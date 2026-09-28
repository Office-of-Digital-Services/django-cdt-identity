from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("django-cdt-identity")
except PackageNotFoundError:
    # package is not installed
    __version__ = ""


VERSION = __version__
