"""
### CSVHandler ###
Author: Seth Johnson
Date: 07-14-2023
"""
### Package handling
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time
import pylab as pl
import random
from pprint import pprint

### Variable Declaration
apkData = -1 # DataFrame of all APK data harvested from APKScanner.py
apks = -1 # NumPy array that lists apk file hashes
avRanks = -1 # NumPy Array that lists the AV Ranking for each file
permKeys = [] # Key values for the permissions requested by a given APK file. This is for reference for our perms array
keys = [] # Lables of CSV data that is NOT the permissions requested by a given APK file
perms = -1 # "Features". NumPy array consisting of arrays which hold the permission attributes for a given element in apks @ the same index. First two elements indicate AV Rank, and Total Permissions Requested. Subsequent elements are a binary representation of the types of permissions the apk file requests.
labels = [] # "Labels". Array of arrays of 0s(benign) or 1s(malicious). Matches index values with apks and avRanks to indicate if apk file is malicious

### UDF Declaration
def preprocessing(CSV_FILE):
    """
    ### Parses CSV file passed as a parameter to prep for execution later
    Returns variables if successful, 0 otherwise
    """
    global apkData
    global permKeys
    global apks
    global avRanks
    global labels
    global perms
    try:
        print(f"### CONSOLE: Reading {CSV_FILE}...")

        apkData = pd.read_csv(CSV_FILE) # Calling CSV and filling DataFrame (DF)

        # Building keys array for parsinng reference later
        for i in range(6):
            keys.append(apkData.keys()[i])

        permKeys = apkData.loc[0].keys().drop(i for i in keys).values # Key values for the permissions requested by a given APK file. This is for reference for our features array
        apks = apkData["APK File"].values # Pulling APK files to correlate labels
        avRanks = apkData["AV Rank"].values # pulls AV Rank from csv DF
        labels = [1 if i > 0 else 0 for i in avRanks] # builds an array of malware classification based off avRank

        perms = [apkData.loc[i].drop((i for i in keys)).values for i in range(len(apkData))] # Genereating features array that drops first 6 columns to include the total permissions requested, followed by the PermSpread
        print("### CONSOLE: Preprocessing complete.")
        
        return apkData, keys, permKeys, apks, avRanks, perms, labels

    except Exception as e:
        print(f"### CONSOLE: Failure occured.\n{e}\nExiting...")
        return 0

def verifyPreprocessing(): # Writes a structured output to a file of all data parsed out of csv's DF
    with open("2023_REU_Workspace/stupid.txt", "w") as outFile:
        for i in range(len(apks)):
            outFile.write("Application: " + apkData.loc[i].loc["Application Name"] + "\n")
            outFile.write("Package: " + apkData.loc[i]["Package Name"] + "\n")
            outFile.write(f"APK File: {apks[i]}" + "\n")
            outFile.write(f"AV Rank: {avRanks[i]}" + "\n")
            outFile.write(f"Total Permissions Requested: {sum(perms[i][2:])}" + "\n")
            outFile.write(f"Permission Spread: {perms[i]}" + "\n")
            arr = []
            for j in range(2, len(permKeys)):
                if perms[i][j] > 0:
                    arr.append(permKeys[j])
            outFile.write(f"Permissions requested: {arr}")
            outFile.write("\n")
    return 1

if __name__ == "__main__":
    print(os.getcwd()) # Displaying script's CWD
    preprocessing("2023_REU_Workspace/COVID19_APK_Data_06-2023.csv")
    verifyPreprocessing()
