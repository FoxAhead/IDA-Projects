from .base import BaseResourceLoader


class TextAme(BaseResourceLoader):
    def parse(self, file_path):
        result = {}
        counter = 0
        with open(file_path, 'r') as file:
            for line in file:
                stripped_line = line.strip()

                if not stripped_line or stripped_line.startswith(';'):
                    continue

                result[counter] = stripped_line
                counter += 1

        return result
