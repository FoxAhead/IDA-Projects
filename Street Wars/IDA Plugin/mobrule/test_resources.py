
from mobrule.resources import Resources

if __name__ == '__main__':
    Resources.load()
    for i, (key, value) in enumerate(Resources["ta"].items(), 1):
        print(f"{key} => {value}")