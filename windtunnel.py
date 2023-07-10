"""
Author: Seth Johnson
Date: 07-07-2023
Details:
- Playground for me to mess around with individual components of the overall Models.ipynb
"""
"""
### TODO
    - limit `perms` to only include AndroidOS base permissions --> TODO
    - percentage of apps that failed analysis
    - Std Dev, Std Err to compare my processed data with the data provided by COVIDMalware.pdf
        - might be useful to includ metric of apks that failed analysis
        - this can help confirm that what I did was right
        - Check Stats 305 stuff to provide formulas and context for these values
    - I'm pretty sure I'm doing the manual K-Folding wrong, so I've gotta re-look @ how to do that
    - Debug CatNB's IndexError --> TODO
    - Prettify Models.ipynb
        - Make graphing functions to reduce redundant code
        - maybe make this a class to implement F.E. classifier??
    
### NOTE
    - Running clf = SVM
        - results seems to sit around 95% Accuracy, 100% Percision, recall ~60%
        - Implemented SMOTE, seems to modify performance metrics with varying degrees
    - Decision Trees still reuslts 100% Accuracy
    - CatNB throws IndexError when calling clf.predict()
"""
### Package Handling
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time
import pylab as pl
import random
from pprint import pprint

### Static Variable Declaration
# !!! CHANGE THESE VALUES IF WE WANT TO TWEAK OUR MODELS !!!!
FOLDS = 5 # How many times our models will iterate through a dataset
RANDOM_STATE = 42 # The entropy of our paritioned datasets. This determines how similar one dataset is to the next.
TEST_SIZE = 0.2 # The percentage of testing data to the training data. 
CSV_FILE = "2023_REU_Workspace/COVID19_APK_Data_06-2023.csv" # CSV File consisting of analyzed APK data

### Variable Declaration
# CSV reference
apkData = -1 # DataFrame of all APK data harvested from APKScanner.py
apks = -1 # NumPy array that lists apk file hashes
avRanks = -1 # NumPy Array that lists the AV Ranking for each file
# Reference arrays
keys = [] # Lables of CSV data that is NOT the permissions requested by a given APK file
permKeys = [] # Key values for the permissions requested by a given APK file. This is for reference for our perms array
osPermKeys = [] # Key values for all permissions associated with the base AndroidOS devkit
# Separating permission spreads between benign and malicious apk tyes
permSpread = [] # Array of arrays representing the permissions that a given apk file requests
osPermSpread = [] # Array of arrays representing permission spread of all apk base AndroidOS requests

benignSpread = [] # Array of arrays that represent all permissions that a benign APK file requests
maliciousSpread = [] # Array of arrays that represent all permissions that a malicious APK file requests
benignSpread_OS = [] # Array of arrays representing all AndroidOS permissions that a benign APK file requests
maliciousSpread_OS = [] # Array of arrays representing all AndroidOS permissions that a malicious APK file requests

benignSpread_sums = [] # Array representing the total sum of all permissions a given benign apk file requests
maliciousSpread_sums = [] # Array represnting total sum of all permissions a given malicious apk file requests

benignPerms = [] # Array representing how many times a benign APK file requests a given permission. The index of each value represents how many times a permission in permSpread is requested.
maliciousPerms = [] # Array representing how many times a malicious APK file requests a given permission. The index of each value represents how many times a permission in permSpread is requested.
benignPerms_OS = [] # Array representing how many times a benign APK file requests a given AndroidOS permission
maliciousPerms_OS = [] # Array representing how many times a malicious APK file requests a given AndroidOS permission
# for our models
perms = -1 # "Features". NumPy array consisting of arrays which hold the permission attributes for a given element in apks @ the same index. First two elements indicate AV Rank, and Total Permissions Requested. Subsequent elements are a binary representation of the types of permissions the apk file requests.
labels = [] # "Labels". Array of arrays of 0s(benign) or 1s(malicious). Matches index values with apks and avRanks to indicate if apk file is malicious
permSMOTE = [] # Array of the features treated with SMOTE
labelSMOTE = [] # Array of the lables treated with SMOTE
xTrain = -1 # Array consisting training features. This is passed into fit() methods
xTest = -1 # Array consisting of testing features. Predictions will use this variable.
yTrain = -1 # Array consisting of training labels. Pass into fit() methods for supervised learning.
yTest = -1 # Array consisting of testing labels. This assists with metrics, and backpropogation
confusion = -1 # 2D Array built to represent True/False Positives to calculate Recall and Percision metrics
clf = -1 # Classifier variable to assign to different models
prediction = -1 # Array consisting of the results of a classifier's prediction call
ssplit = -1 # Cross-Validation object created by sklearn's ShuffleSplit(). Passed as a CV parameter for cross_val_score()
scores = -1 # Array consisting of metrics from sklearn's cross_val_score()
# visual aids
x = [] # Array for representing the quantity of permissions requested across all analyzed APK files
yBenign = [] # Array representing how many APK files request a certain number of permissions. Each index correlates to the index in `x`, and the value at each index represents how many benign APK files request that many permissions
yMalicious = [] # Array representing how many APK files request a certain number of permissions. Each index correlates to the index in `x`, and the value at each index represents how many malicious APK files request that many permissions
t0 = 0 # float value for recording a model's performance duration

### Function Declaration

def verifyPreprocessing(): # Writes a structured output to a file of all data parsed out of csv's DF
    with open("stupid.txt", "w") as outFile:
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

def visualize(xArr, yArrs, title=None, x_Axs=None, y_Axs=None, save=False, flip=False):
    """
    @Description: Utilizes Matplotlib.pyplot to provide superimposed plots for my research

    @params
    xArr:= Array used for plotting along the x axis
    yArrs:= Array consisting of all values that wish to be superimposed on the same image
    title:= String used to label the graph. Defaults to None
    save:= Boolean that determines if the plot is to be saved as a .png. title must be provided if set to True. Defaults to False
    flip:= Boolean to flip the graph to a horizontal bar graph. Defaults to False
    x_Axs:= String to label the X-axis of a plot
    y_Axs:= String to label the y-axis of a plot

    @returns 1 if successful, 0 Otherwise
    """
    if flip:
        for i in range(len(yArrs)):
            plt.barh(xArr, yArrs[i], label=i)
    else:
        for i in range(len(yArrs)):
            plt.bar(xArr, yArrs[i], label=i)

    if x_Axs != None:
        plt.xlabel(x_Axs)
    if y_Axs != None:
        plt.ylabel(y_Axs)

    if title != None:
        plt.title(title)

    plt.legend()

    if save:
        if title == None:
            raise Exception("No title provided, plot will not be saved.")
            return 0
        plt.savefig(f"{title}.png", dpi=300, bbox_inches="tight")

    plt.show()

    return 1

"""
### PREPROCESSING
"""
print(os.getcwd()) # Displaying shell's CWD

print(f"### CONSOLE: Reading {CSV_FILE}...")

apkData = pd.read_csv(CSV_FILE) # Calling CSV and filling DataFrame (DF)

"""
### Scraping our CSV's DF
"""
# Building keys array for parsinng reference later. Also builds permKey array for the permissions requested by a given APK file. This is for reference for our features array
for i in range(len(apkData.keys())):
    keys.append(apkData.keys()[i]) if (i < 6) else permKeys.append(apkData.keys()[i])

permKeys.insert(0, "AV Rank") # Including AV Rank to permKeys reference

apks = apkData["APK File"].values # Pulling APK files to correlate labels
avRanks = apkData["AV Rank"].values # pulls AV Rank from csv DF
labels = [1 if i > 0 else 0 for i in avRanks] # builds an array of malware classification based off avRank. <-- This will be our labels

perms = [apkData.loc[i].drop((i for i in keys)).values for i in range(len(apkData))] # Genereating features array that drops first 6 columns to include the total permissions requested, followed by the PermSpread
# Prepending AV Rank to each sub-array in perms for our features set
for i in range(len(perms)):
    perms[i] = np.insert(perms[i], 0, avRanks[i]) # <-- This will be our features

# verifyPreprocessing() # Verifying that everything went smoothly

print("### CONSOLE: Preprocessing complete...")

"""
### Pre-modelling statistics
"""
### Prepping our arrays
for i in range(len(perms)):
    permSpread.append(perms[i][2:]) # cleaning permission spread of AV Rank and total permission requests

    # Creating keys and permSpread arrays specifically for AndroidOS-based permissions
    arr = [] # subarray for our osPermSpread
    for ef in range(len(permKeys)):
        if permKeys[ef].lower().startswith("android.permission"):
            if permKeys[ef] not in osPermKeys: # keeps from multiplying immensely
                osPermKeys.append(permKeys[ef]) # Builds osPerms key array
            arr.append(perms[i][ef])
    osPermSpread.append(arr) # updating osPermSpread with our subarray

benignPerms = [0 for _ in range(len(permKeys))]
maliciousPerms = [0 for _ in range(len(permKeys))]
benignPerms_OS = [0 for _ in range(len(osPermKeys))]
maliciousPerms_OS = [0 for _ in range(len(osPermKeys))]

for i in range(len(apks)):
    if labels[i] > 0:
        maliciousSpread.append(permSpread[i]) # Sorting out malicious permission spreads
        maliciousSpread_OS.append(osPermSpread[i]) # ...and for OS specific permissions
        for j in range(len(permSpread[i])): 
            maliciousPerms[j] += permSpread[i][j] # building an array of ints representing malicious requests FE permission
        # restricting to only AndroidOS permissions...
        for j in range(len(osPermSpread[i])): 
            maliciousPerms_OS[j] += osPermSpread[i][j]
    else:
        benignSpread.append(permSpread[i]) # Sorting out benign permission spreads
        benignSpread_OS.append(osPermSpread[i]) # ...and for OS specific permissions
        for j in range(len(permSpread[i])): 
            benignPerms[j] += permSpread[i][j] # building an array of ints representing benign requests FE permission
        # restricting to only AndroidOS permissions...
        for j in range(len(osPermSpread[i])):
            benignPerms_OS[j] += osPermSpread[i][j]

# Collecting the sum of each array in malicious/benignSpread
benignSpread_sums = [sum(i) for i in benignSpread]
maliciousSpread_sums = [sum(i) for i in maliciousSpread]

# Building the x-array to display each APK's total permission request, distinguished by AV Rank > 0
x = [i for i in range(max(maliciousSpread_sums) + 1)] if maliciousSpread_sums > benignSpread_sums else [i for i in range(max(benignSpread_sums) + 1)]

# Building y-arrays to display each APK's total permission request, distinguished by AV Rank > 0
yBenign = [0 for _ in range(len(x))]
yMalicious = [0 for _ in range(len(x))]

for i in benignSpread_sums:
    yBenign[i] += 1

for i in maliciousSpread_sums:
    yMalicious[i] += 1

### Re-Doing yBenign and yMalicious for our OS specific permission spreads

benignSums = [sum(i) for i in benignSpread_OS]
maliciousSums = [sum(i) for i in maliciousSpread_OS]

# Resetting y arrays
yBenign = [0 for _ in range(len(x))]
yMalicious = [0 for _ in range(len(x))]

for i in benignSums:
    yBenign[i] += 1

for i in maliciousSums:
    yMalicious[i] += 1

# Proportional frequency of APK files that requested only base AndroidOS permissions
title = "Proportional frequency of APK files that request only base AndroidOS permissions"
xLabel = "Quantity of AndroidOS permissions requested"
yLabel= "Proportional frequency of APK files"
visualize(x, [[i / len(benignSpread_OS) for i in yBenign], [i / len(maliciousSpread_OS) for i in yMalicious]], title=title, x_Axs=xLabel, y_Axs=yLabel, save=True)

# Proportional frequency of APK files that requested only base AndroidOS permissions up to 60 times
title = "Proportional frequency of APK files that request only base AndroidOS permissions up to 60 times"
visualize(x[:60], [[i / len(benignSpread_OS) for i in yBenign[:60]], [i / len(maliciousSpread_OS) for i in yMalicious[:60]]], title=title, x_Axs=xLabel, y_Axs=yLabel, save=True)

# Frequency of applications requesting base AndroidOS permissions
title = "Frequency of requests for each base AndroidOS permission"
xLabel = "AndroidOS Permissions"
yLabel = "Frequency of APK file requests"
# visualize(osPermKeys, [benignPerms_OS, maliciousPerms_OS], title=title, x_Axs=xLabel, y_Axs=yLabel, flip=True, save=True)

# Frequency of applications requesting the first 30 base AndroidOS permissions
title = "Frequency of requests for the first 30 base AndroidOS permission"
visualize(osPermKeys[:30], [benignPerms_OS[:30], maliciousPerms_OS[:30]], title=title, x_Axs=xLabel, y_Axs=yLabel, flip=True, save=True)

# Proportion of applications requesting the first 30 base AndroidOS permissions
title = "Proportional frequency of requests for the first 30 base AndroidOS permission"
visualize(osPermKeys[:30], [[i / len(benignPerms_OS) for i in benignPerms_OS[:30]], [i / len(maliciousPerms_OS) for i in maliciousPerms_OS[:30]]], title=title, x_Axs=xLabel, y_Axs=yLabel, flip=True, save=True)

"""
### Scikit-Learn
"""

"""
### Deep Neural Networks
"""