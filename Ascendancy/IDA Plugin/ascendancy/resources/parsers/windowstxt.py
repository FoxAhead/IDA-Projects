from .base import BaseResourceLoader


class WindowsTxt(BaseResourceLoader):
    def parse(self, file_path):
        result = {}
        with open(file_path, 'r') as file:
            while line := file.readline():
                line1 = line.strip()
                if line1.startswith("TYPE"):
                    line2 = file.readline().strip()
                    if line2.startswith("NAME"):
                        line3 = file.readline().strip()
                        if line3.startswith("PARENT"):
                            s, wnd_type = line1.split()
                            s, wnd_name = line2.split()
                            s, wnd_parent = line3.split()
                            wnd_typen = int(wnd_type)
                            if wnd_typen > 0:
                                result[wnd_name] = wnd_typen
        return result
