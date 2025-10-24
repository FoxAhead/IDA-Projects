from .base import BaseResourceLoader


class GwshareTxt(BaseResourceLoader):
    def parse(self, file_path):
        result = {}
        with open(file_path, 'r') as file:
            i = 0
            while line := file.readline():
                line1 = line.strip()
                if line1 and line1 != '\x1a':
                    result[i] = line1
                    i += 1
        return result
