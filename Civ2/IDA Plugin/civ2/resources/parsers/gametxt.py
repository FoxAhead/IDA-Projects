from .base import BaseResourceLoader


class GameTxt(BaseResourceLoader):
    def parse(self, file_path):
        result = {}  # Dict[SectionName, Title]
        with open(file_path, 'r') as file:
            section = ''
            title = ''
            prev_line = ''
            while line_ := file.readline():
                line = line_.strip()
                if line and line.startswith('@') and not prev_line:
                    section = line[1:]
                    result[section] = ''
                elif section:
                    if not line:
                        section = ''
                        title = ''
                    elif line.startswith('@title='):
                        title = line[7:]
                        result[section] += line_
                    elif title:
                        if line.startswith('@'):
                            pass
                            # if not line.startswith('@width=') and not line.startswith('@options='):
                            #     title = ''
                        else:
                            result[section] += line_
                prev_line = line
        #print(result)
        return result
