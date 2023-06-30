#!/usr/bin/python
"""
Author: Seth Johnson
Date: Jun 27, 2023
"""

import os
import csv
import time
import threading
import openpyxl
import concurrent.futures
from subprocess import run
from pprint import pprint
from androguard import misc
import traceback

"""
### Variable Declaration
"""

# dirPath = os.getcwd() + "2023_REU_Workspace/covid_19_Dataset" # For when I wanna run in terminal
dirPath = "2023_REU_Workspace/covid_19_Dataset" # Codium executive path
directory = os.listdir(dirPath) # Get's child directories to iterate through, I really wish to consolidate this further
keys = ["Application Name", "Package Name", "APK File", "AV Rank", "Cloned", "Apps sharing APK", "Total permission requests"] # Reference keys for apk data
dummy = { # To demonstrate how I wanted to structure our data for the csv files
    "App Name" : {
        "256hash.apk": {
            "pkg name": "name of apk's package",
            "permissions": ["Permission spread for the given apk file"],
            "avRank": "integer > -1 representing AV Rank collected during COVIDMalware.pdf study",
            "cloned": "boolean determining if this apk has been cloned",
            "clones": "array of strings of apps that also use this apk file"
        }
    }
}

permSpread = [] # list of all permissions requested across all APK files.
files = [] # declaring list for apk
apps = {} # Declaring dictionary for APK data

"""
### Function Declaration
"""

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

    # Filters out Zip files within directory
    for file in directory:
        if len(os.path.splitext(file)[1]) != 0:
            filePath = os.path.join(dirPath, file)
            zips.append(filePath) if os.path.splitext(file)[1] == ".zip" else print(f"{filePath} is not a zip file")
    
    t0 = time.time()

    ### DANGER: MULTITHREADING
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(unzip, zips)

    print(f"Analysis Duration: {(time.time()-t0):.2f} second(s)") # Time the performace of my program

def apkAnalyzer(apk): # Calls Androguard's misc.AnalyzeAPK() and updates declared dictionary
    print(f"### CONSOLE: Analyzing file: {apk}...")
    global apps

    # Attempt to call Androguard's APK Scanner
    try:
        a, b, c = misc.AnalyzeAPK(apk)
            
        name = a.get_app_name()
        pkg = a.get_package()
        permissions = a.get_permissions()
        apk = apk.split("/")[-1]
        avRank = 0
        cloned = 0
        clones = []

        # Checking if duplicate APKs are found and which apps use them
        for app in apps:
            if apk in apps[app].keys():
                # For the current APK
                cloned = 1 
                clones.append(app)

                # if other APKs are found, update them too
                apps[app][apk]["clones"].append(name)
                apps[app][apk]["cloned"] = 1

        # Collect AV Rank from COVIDMalware.pdf data
        wb = openpyxl.load_workbook(os.path.join(dirPath, "covid19apps.xlsx"))
        for sheet in wb.worksheets:
            for r in range(2, sheet.max_row):
                if sheet.cell(r, 6).value in apk:
                    avRank = sheet.cell(r, 5).value

        # Update Apps dictionary
        if name not in apps:
            apps[name] = {
                apk: {
                    "pkg name": pkg,
                    "permissions": permissions,
                    "avRank": avRank,
                    "cloned": cloned,
                    "clones": clones,
                }
            }
        else:
            if apk not in apps[name]:
                apps[name][apk] = {
                    "pkg name": pkg,
                    "permissions": permissions,
                    "avRank": avRank,
                    "cloned": cloned,
                    "clones": clones,
                }
        print(f"### CONSOLE: Completed analysis.")
    except Exception as ex:
        print(traceback.format_exc())
        print(f"### CONSOLE: Error while analyzing {apk}. Aborting attempt.")
        # # Seeing how many cause us problems and why
        # with open(os.path.join("2023_REU_Workspace", "AnalysisFailures.txt"),"a+") as outFile:
        #     outFile.write(f"{apk} failed with error: {ex}\n")
"""
### INIT MAIN
"""
if __name__ == '__main__':
    """
    ### Compiles list of apk files
    """
    # Really wish I would've condensed both of these loops of 'directory' into a single block
    for file in directory:
        if ".zip" in os.path.splitext(file)[1]:
            print("### CONSOLE: ZipFiles Found.")
            unzipDir(dirPath) # WARNING: THIS WILL UNZIP ALL FILES WITHIN THE DIRECTORY

    # Bonus points for reducing time compelxity here too
    for item in directory:
        if len(os.path.splitext(item)[1]) == 0:
            for file in os.listdir(os.path.join(dirPath, item)):
                files.append(os.path.join(dirPath, item, file))

    # with open(os.path.join("2023_REU_Workspace", "APKsFound.txt"), "w") as outFile:
    #     for file in files:
    #         outFile.write(file+"\n")

    """
    ### APK Analysis
    """
    t0 = time.time() # Start timer

    ### DEBUG: Single file analysis
    # apkAnalyzer(files[0])
    # apkAnalyzer("2023_REU_Workspace/covid_19_Dataset/covid19apps_0526_6/e7d62b7443ad21d5ab9f9cc61adebe110e116b72c5bda90b74dd80a0c9e354d8.apk")
    
    # iterative execution
    # for file in files:
    #     apkAnalyzer(file)

    # Multithreaded execution
    # with concurrent.futures.ThreadPoolExecutor() as executor: # No restrictions with how much threads this program can run
    #     executor.map(apkAnalyzer, files) # Analyzing entirety of files array

    print(f"Analysis Duration: {(time.time()-t0):.2f} second(s)") # Time the performace of my program

    """
    ### Updating keys array
        - to include all permissions found during our APK analysis
    """

    # ### DEBUG: Pre-structured Apps dictionary
    apps = {'Covid 19': {
        '30fce6b41858aadce710ef2ad5f9b3afbd47c32bee70469b112cfa14f60085e9.apk': {
            'avRank': 0,
            'cloned': 0,
            'clones': [],
                    'permissions': ['android.permission.INTERNET'],
                    'pkg name': 'com.urufu.covid19app'
            },
            '493e52c126be18efa077932250d82f764ab2da59d83b5f56d53fe95c1d6ba3bc.apk': {
                'avRank': 4,
                    'cloned': 0,
                    'clones': [],
                    'permissions': [
                'android.permission.SET_WALLPAPER',
                    'android.permission.KILL_BACKGROUND_PROCESSES',
                    'com.anddoes.launcher.permission.UPDATE_COUNT',
                    'android.permission.INTERNET',
                    'android.permission.BROADCAST_PACKAGE_REPLACED',
                'com.oppo.launcher.permission.WRITE_SETTINGS',
                    'android.permission.CALL_PHONE',
                    'android.permission.PROCESS_OUTGOING_CALLS',
                    'android.permission.WAKE_LOCK',
                    'android.permission.READ_EXTERNAL_STORAGE',
                'com.huawei.android.launcher.permission.WRITE_SETTINGS',
                    'android.permission.RECEIVE_SMS',
                    'android.permission.SET_WALLPAPER_HINTS',
                    'com.sonyericsson.home.permission.BROADCAST_BADGE',
                'com.sonymobile.home.permission.PROVIDER_INSERT_BADGE',
                    'com.huawei.android.launcher.permission.CHANGE_BADGE',
                    'com.sec.android.provider.badge.permission.WRITE',
                'com.android.browser.permission.READ_HISTORY_BOOKMARKS',
                    'com.oppo.launcher.permission.READ_SETTINGS',
                'android.permission.READ_PHONE_STATE',
                    'android.permission.ACCESS_COARSE_LOCATION',
                    'android.permission.CAMERA',
                    'android.permission.CHANGE_WIFI_STATE',
                    'android.permission.READ_CONTACTS',
                    'android.permission.WRITE_CONTACTS',
                    'android.permission.READ_CALL_LOG',
                    'android.permission.WRITE_CALL_LOG',
                    'android.permission.FLASHLIGHT',
                    'android.permission.SYSTEM_ALERT_WINDOW',
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'me.everything.badger.permission.BADGE_COUNT_WRITE',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.BROADCAST_PACKAGE_ADDED',
                'android.permission.BROADCAST_PACKAGE_CHANGED',
                    'android.permission.READ_SMS',
                    'com.htc.launcher.permission.READ_SETTINGS',
                    'android.permission.VIBRATE',
                    'android.permission.RECEIVE_BOOT_COMPLETED',
                    'com.sec.android.provider.badge.permission.READ',
                'me.everything.badger.permission.BADGE_COUNT_READ',
                'android.permission.BROADCAST_PACKAGE_INSTALL',
                'android.permission.READ_APP_BADGE',
                'android.permission.BLUETOOTH',
                'android.permission.ACCESS_NETWORK_STATE',
                'android.permission.ACCESS_WIFI_STATE',
                'android.permission.ACCESS_FINE_LOCATION',
                'com.htc.launcher.permission.UPDATE_SHORTCUT',
                'com.huawei.android.launcher.permission.READ_SETTINGS',
                'android.permission.GET_TASKS',
                'android.permission.GET_ACCOUNTS',
                'com.majeur.launcher.permission.UPDATE_BADGE'
            ],
            'pkg name': 'cmf0.c3b5bm90zq.patch'
        },
        '86e93e44371566b39402b2e455f59b06ce0628d63c9f7a9b0bf7a5ebe8821b2b.apk': {
            'avRank': 0,
                    'cloned': 0,
            'clones': [],
            'permissions': ['android.permission.INTERNET'],
            'pkg name': 'com.urufu.covid19app'
        },
        'c21da66789e5b45a69a2373a3569478eaaf3e8ed036329324fd5e4be939ac2a6.apk': {
            'avRank': 0,
            'cloned': 0,
            'clones': [],
            'permissions': [
                'android.permission.ACCESS_NETWORK_STATE',
                'android.permission.INTERNET'
            ],
            'pkg name': 'com.app.covid19'
        }
    }}

    # pprint(apps)

    # Aggregating all requested permissions
    for app in apps:
        for key, values in apps[app].items():
            for i in values["permissions"]:
                permSpread.append(i) if i not in permSpread else print("",end="")

            
    # print(permSpread)
    permSpread.sort()
    keys += permSpread
    # print(keys[7:])
    
    """
    ### Writing to CSV
    """

    for app in apps:
        for apk, values in apps[app].items():
            line = [] # THIS FUCK WAS IN THE OUTER LOOP AND DUPLICATED MY CSV LINES
            # print(f"Application Name: {app}")
            line.append(app)
            # print("Package Name: ", values["pkg name"])
            line.append(values["pkg name"])
            # print(f"APK File: {key}")
            line.append(apk)
            # print("AV Rank: ", values["avRank"])
            line.append(values["avRank"])
            # print(f"{apk} has been cloned.") if values["cloned"] > 0 else print("", end="")
            line.append(values["cloned"])
            # print(f"Apps sharing {apk}: ", values["clones"])
            line.append(values["clones"])
            # print("Total permssion requests: ", len(values["permissions"]))
            line.append(len(values["permissions"]))
            # print("Permissions spread: ", values["permissions"])
            for i in keys[7:]:
                line.append(1) if i in values["permissions"] else line.append(0)

            # Will not include the Malware (y/n) col, since I feel the AV Rank satisfies that metric
            # print(f"\n###{key} is malware!!###\n") if values["avRank"] > 0 else print("APK is benign.")
            
            print(line)

    # with open(os.path.join(os.getcwd(), "2023_REU_Workspace/resultsPt2.csv"), 'w') as outFile:
    #     writer = csv.writer(outFile)
    #     writer.writerow(keys)
    #     for app in apps:
    #         for apk, values in apps[app].items():
    #             line = [] # THIS FUCK WAS IN THE OUTER LOOP AND DUPLICATED MY CSV LINES
    #             # print(f"Application Name: {app}")
    #             line.append(app)
    #             # print("Package Name: ", values["pkg name"])
    #             line.append(values["pkg name"])
    #             # print(f"APK File: {key}")
    #             line.append(apk)
    #             # print("AV Rank: ", values["avRank"])
    #             line.append(values["avRank"])
    #             # print(f"{apk} has been cloned.") if values["cloned"] > 0 else print("", end="")
    #             line.append(values["cloned"])
    #             # print(f"Apps sharing {apk}: ", values["clones"])
    #             line.append(values["clones"])
    #             # print("Total permssion requests: ", len(values["permissions"]))
    #             line.append(len(values["permissions"]))
    #             # print("Permissions spread: ", values["permissions"])
    #             for i in keys[7:]:
    #                 line.append(1) if i in values["permissions"] else line.append(0)

    #             # Will not include the Malware (y/n) col, since I feel the AV Rank satisfies that metric
    #             # print(f"\n###{key} is malware!!###\n") if values["avRank"] > 0 else print("APK is benign.")
                
    #             print(line)
    #             # writer.writerow(line)
    
    # print("Current datastructure Format:")
    # pprint(dummy)

    """
    ### Problems and errors
    - My spreadsheet's all screwed up, I coded it wrong :(
        -   I KNOW WHY: THE ARRAY DECLARATION WAS IN ONE LOOP TO HIGH
    """

    """
    ### Notes on what to do
    - Machine Learning part --> 90% accuracy
        - compare N-B, SVM, DTrees
        - metrics comparison: f1, percision, accuracy, recall, time, etc.
        - K-Fold Cross-Validation to partition and work through our full dataset
        
    - NN part --> Shoot for 98% accuracy
        - passing to DNN
        - converting to image map for C/ANN
        
    - For the best model
        - Fine tune it!!!
        
    - Step 3
        - SMOTE to assist balancing dataset
            - 5 with SMOTE applied, 5 without SMOTE applied
        - Comparing to prepared xlsx given
        
    - replicate bar graph from COVIDMalware.pdf representing how many apps use a specific permission

    - graph how many apps use a quantity of permissions
        - sum all 1 values in permissions in csv 
    """
