from .base import BaseResourceLoader


class StaticTxt(BaseResourceLoader):
    def parse(self, file_path):
        result = {}
        with open(file_path, 'r') as file:
            while line := file.readline():
                if line.startswith("//"):
                    tokens = line[2:].strip().replace(' ', '')
                    tokens = tokens.split('-')
                    if len(tokens) > 0 and tokens[0].isdigit():
                        val1 = int(tokens[0])
                        val2 = val1
                        if len(tokens) > 1 and tokens[1].isdigit():
                            val2 = int(tokens[1])
                        for i in range(val1, val2 + 1):
                            if val1 < val2:
                                text = file.readline()
                            else:
                                text = ''
                                while (line := file.readline()) != '\n':
                                    text = text + line
                            result[i] = text.rstrip()
                            #if self.debug:
                            #    print("%d: %s" % (i, self.texts[i]))
        return result
