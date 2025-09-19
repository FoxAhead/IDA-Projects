import os


class GwshareTxt(object):
    names = {}

    def __init__(self, filename, debug=False):
        self.filename = filename
        self.debug = debug
        self._load()

    def _load(self):
        script_dir = os.path.dirname(__file__)
        filename = os.path.join(script_dir, self.filename)
        with open(filename, 'r') as file:
            i = 0
            while line := file.readline():
                line1 = line.strip()
                if line1 and line1 != '\x1a':
                    GwshareTxt.names[i] = line1
                    i += 1


if __name__ == '__main__':
    lgt = GwshareTxt("gwshare.txt", True)
    print(GwshareTxt.names)
else:
    gt = GwshareTxt("gwshare.txt", False)
