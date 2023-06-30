"""
Author: Seth Johnsno
Date: Jun 10, 2023
#############################################################
# Directory Unzipper
# UNZIPS ALL ZIPFILES IN A GIVEN DIRECTORY
#############################################################
"""

import os
from subprocess import run
import concurrent.futures
import time
from pprint import pprint

def unzip(filePath):
    print(f"# CONSOLE: Unzipping {filePath}...")

    try:
        run(["unzip", filePath, "-d", dirPath])
        print(f"# CONSOLE: unzipped {filePath}. Deleting zipfiles...")
        os.remove(filePath)
    except:
        print(f"# CONSOLE: Unable to unzip {filePath}.")

def unzipDir(dirPath):
    zips = []

    for file in directory:
        if len(os.path.splitext(file)[1]) != 0:
            filePath = os.path.join(dirPath, file)
            zips.append(filePath) if os.path.splitext(file)[1] == ".zip" else print(f"{filePath} is not a zip file")
    
    start = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(8) as executor:
        executor.map(unzip, zips)

    finish = time.perf_counter()
    print(f"Time spent unzipping files: {(finish - start):.2f} second(s)")

# dirPath = os.getcwd() + "2023_REU_Workspace/covid_19_Dataset" # For when I wanna run in terminal
dirPath = "2023_REU_Workspace/covid_19_Dataset" # Codium executive path

directory = os.listdir(dirPath)
pprint(directory)

for file in directory:
    if ".zip" in os.path.splitext(file)[1]:
        unzipDir(dirPath)

