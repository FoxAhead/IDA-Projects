from .base import BaseResourceLoader


class LabelsTxt(BaseResourceLoader):
    def parse(self, file_path):
        i = -1
        result = []
        with open(file_path, 'r') as file:
            while line := file.readline():
                if i >= 0:
                    result[i] = line.rstrip()
                    # print("%d: %s" % (i, self.labels[i]))
                    i += 1
                elif line.startswith("@LABELS"):
                    line = file.readline()
                    val = int(line)
                    result = [''] * val
                    i = 0
        return result
