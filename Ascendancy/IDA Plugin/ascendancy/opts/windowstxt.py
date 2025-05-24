import os


class WindowsTxt(object):
    names = {}

    def __init__(self, filename, debug=False):
        self.filename = filename
        self.debug = debug
        self._load()

    def _load(self):
        script_dir = os.path.dirname(__file__)
        filename = os.path.join(script_dir, self.filename)
        with open(filename, 'r') as file:
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
                            # if wnd_parent == "NONE" and wnd_typen > 0:
                            if wnd_typen > 0:
                                #print("ADDING", wnd_name, wnd_typen)
                                #if wnd_name in WindowsTxt.names:
                                #    print(wnd_name, "EXISTS!")
                                WindowsTxt.names[wnd_name] = wnd_typen

                    # tokens = line[2:].strip().replace(' ', '')
                    # tokens = tokens.split('-')
                    # if len(tokens) > 0 and tokens[0].isdigit():
                    #     val1 = int(tokens[0])
                    #     val2 = val1
                    #     if len(tokens) > 1 and tokens[1].isdigit():
                    #         val2 = int(tokens[1])
                    #     for i in range(val1, val2 + 1):
                    #         if val1 < val2:
                    #             text = file.readline()
                    #         else:
                    #             text = ''
                    #             while (line := file.readline()) != '\n':
                    #                 text = text + line
                    #         self.texts[i] = text.rstrip()
                    #         if self.debug:
                    #             print("%d: %s" % (i, self.texts[i]))


if __name__ == '__main__':
    lwt = WindowsTxt("windows.txt", True)
    print(WindowsTxt.names)
else:
    wt = WindowsTxt("windows.txt", False)
