
def get_content(path: str):
    with open(file=path, mode="r") as reader:
        content = reader.readlines()
        content = [line.strip() for line in content]
    return content
