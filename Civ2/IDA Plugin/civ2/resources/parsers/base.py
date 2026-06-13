from abc import ABC, abstractmethod
from pathlib import Path


class BaseResourceLoader(ABC):

    def __init__(self, filename: str):
        self.filename = filename
        self._data = None
        self._loaded = False

    def _get_file_path(self) -> Path:
        current_dir = Path(__file__).parent.parent
        return current_dir / "data" / self.filename

    def load(self) -> None:
        file_path = self._get_file_path()

        if not file_path.exists():
            raise FileNotFoundError(f"Resource file not found: {file_path}")

        try:
            self._data = self.parse(str(file_path))
            self._loaded = True
            print("Loaded %s" % file_path)

        except Exception as e:
            raise IOError(f"Failed to load resource {self.filename}: {e}")

    @abstractmethod
    def parse(self, file_path: str):
        pass

    @property
    def data(self):
        if not self._loaded:
            self.load()
        return self._data

    @property
    def is_loaded(self) -> bool:
        return self._loaded
