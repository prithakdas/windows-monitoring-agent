import json

def load_json(file_path):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except Exception:
        return {}