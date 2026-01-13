import os
from civ2.config import Config

LABELS_FNAMES = ["labels.txt", "labelsToT.txt"]


class StaticTexts(object):
    labels = []
    improve = []

    def __init__(self, debug=False):
        self.debug = debug
        self._load_labels()
        self._load_rules()

    def _load_labels(self):
        script_dir = os.path.dirname(__file__)
        labels_fname = Config.get_name_address("LABELS_FNAME")
        filename = os.path.join(script_dir, labels_fname)
        i = -1
        self.labels.clear()
        with open(filename, 'r') as file:
            while line := file.readline():
                if i >= 0:
                    self.labels[i] = line.rstrip()
                    if self.debug:
                        print("%d: %s" % (i, self.labels[i]))
                    i += 1
                elif line.startswith("@LABELS"):
                    line = file.readline()
                    val = int(line)
                    self.labels = [''] * val
                    i = 0
        print('Civ2 plugin: %s loaded' % filename)

    def _load_rules(self):
        script_dir = os.path.dirname(__file__)
        filename = os.path.join(script_dir, "RULES.TXT")
        i = -1
        with open(filename, 'r') as file:
            while line := file.readline():
                if line.startswith("@IMPROVE"):
                    i = 0
                elif line == '\n':
                    i = -1
                elif i >= 0:
                    self.improve.append(line.rstrip().split(',')[0])
                    if self.debug:
                        print("%d: %s" % (i, self.improve[i]))
                    i += 1


st = None


def load_static_texts():
    global st
    if st is None:
        st = StaticTexts(False)

# if __name__ == '__main__':
#    st = StaticTexts(False)
