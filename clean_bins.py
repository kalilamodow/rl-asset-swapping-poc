import os

for file in os.listdir():
    if file.endswith((".bin", ".upk")):
        os.remove(file)
