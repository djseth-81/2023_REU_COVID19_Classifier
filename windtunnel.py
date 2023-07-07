"""
Author: Seth Johnson
Date: 07-07-2023
Details:
- Playground for me to mess around with individual components of the overall Models.ipynb
"""
"""
### TODO
    - limit `perms` to only include AndroidOS base permissions
    - percentage of apps that failed analysis
    - Std Dev, Std Err to compare my processed data with the data provided by COVIDMalware.pdf
        - might be useful to includ metric of apks that failed analysis
        - this can help confirm that what I did was right
        - Check Stats 305 stuff to provide formulas and context for these values
    - Restrict to only Android OS applications --> TODO
    - I'm pretty sure I'm doing the manual K-Folding wrong, so I've gotta re-look @ how to do that
    - Debug CatNB's IndexError --> TODO
    - Prettify
        - Make graphing functions to reduce redundant code
        - maybe make this a class to implement F.E. classifier??
    
### NOTE
    - Decision Trees still reuslts 100% Accuracy
    - SVM results in 100% Percision, recall ~60% --> WORKING ON
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

### Variable Declaration
FOLDS = 5 # How many times our models will iterate through a dataset
RANDOM_STATE = 42 # The entropy of our paritioned datasets. This determines how similar one dataset is to the next.
TEST_SIZE = 0.2 # The percentage of testing data to the training data. 
CSV_FILE = "2023_REU_Workspace/COVID19_APK_Data_06-2023.csv" # CSV File consisting of analyzed APK data

keys = [] # Lables of CSV data that is NOT the permissions requested by a given APK file
permKeys = [] # Key values for the permissions requested by a given APK file. This is for reference for our perms array
benignSpread = [] # permission spread requested by benign APK files
maliciousSpread = [] # permission spread requested by APK files flagged by AV software
apkData = -1 # DataFrame of all APK data harvested from APKScanner.py
apks = -1 # NumPy array that lists apk file hashes
avRanks = -1 # NumPy Array that lists the AV Ranking for each file
perms = -1 # "Features". NumPy array consisting of arrays which hold the permission attributes for a given element in apks @ the same index. First two elements indicate AV Rank, and Total Permissions Requested. Subsequent elements are a binary representation of the types of permissions the apk file requests.
labels = [] # "Labels". Array of arrays of 0s(benign) or 1s(malicious). Matches index values with apks and avRanks to indicate if apk file is malicious
permSpread = [] # Array of arrays representing the permissions that a given apk file requests
maliciousSpread = [] # Array of arrays that represent all permissions that a malicious APK file requests
benignSpread = [] # Array of arrays that represent all permissions that a benign APK file requests
maliciousSpread_sums = [] # Array represnting total sum of all permissions a given malicious apk file requests
benignSpread_sums = [] # Array representing the total sum of all permissions a given benign apk file requests
x = [] # Array for representing the quantity of permissions requested across all analyzed APK files
yBenign = [] # Array representing how many APK files request a certain number of permissions. Each index correlates to the index in `x`, and the value at each index represents how many benign APK files request that many permissions
yMalicious = [] # Array representing how many APK files request a certain number of permissions. Each index correlates to the index in `x`, and the value at each index represents how many malicious APK files request that many permissions
benignPerms = [] # Array representing how many times a benign APK file requests a given permission. The index of each value represents how many times a permission in permSpread is requested.
maliciousPerms = [] # Array representing how many times a malicious APK file requests a given permission. The index of each value represents how many times a permission in permSpread is requested.
t0 = 0 # float value for recording a model's performance duration
xTrain = -1 # Array consisting training features. This is passed into fit() methods
xTest = -1 # Array consisting of testing features. Predictions will use this variable.
yTrain = -1 # Array consisting of training labels. Pass into fit() methods for supervised learning.
yTest = -1 # Array consisting of testing labels. This assists with metrics, and backpropogation
confusion = -1 # 2D Array built to represent True/False Positives to calculate Recall and Percision metrics
clf = -1 # Classifier variable to assign to different models
prediction = -1 # Array consisting of the results of a classifier's prediction call
scores = -1 # Array consisting of metrics from sklearn's cross_val_score()

### Function Declaration
def verifyPreprocessing():
    pass

"""
### PREPROCESSING
"""
print(os.getcwd()) # Displaying script's CWD

print(f"### CONSOLE: Reading {CSV_FILE}...")

apkData = pd.read_csv(CSV_FILE) # Calling CSV and filling DataFrame (DF)

"""
### Scraping our CSV's DF
"""
# Building keys array for parsinng reference later
for i in range(6):
    keys.append(apkData.keys()[i])

# print(keys)

permKeys = apkData.loc[0].keys().drop(i for i in keys).values # Key values for the permissions requested by a given APK file. This is for reference for our features array
permKeys = np.insert(permKeys, 0, "AV Rank") # Including AV Rank to permSpread
# print(permSpread)
apks = apkData["APK File"].values # Pulling APK files to correlate labels
avRanks = apkData["AV Rank"].values # pulls AV Rank from csv DF
labels = [1 if i > 0 else 0 for i in avRanks] # builds an array of malware classification based off avRank

perms = [apkData.loc[i].drop((i for i in keys)).values for i in range(len(apkData))] # Genereating features array that drops first 6 columns to include the total permissions requested, followed by the PermSpread
# Prepending AV Rank to each sub-array in perms
for i in range(len(perms)):
    perms[i] = np.insert(perms[i], 0, avRanks[i])
print("### CONSOLE: Preprocessing complete...")

"""
### Scikit-Learn
"""
from sklearn.naive_bayes import CategoricalNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC # importing the Classifier module specifically
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split, KFold


"""
### PARAMETER DECLARATION
"""
clf = SVC(kernel="poly", C=5, gamma='scale')

"""
### Sklearn cross_val_score() module
- https://scikit-learn.org/stable/modules/cross_validation.html
- compare with the current manual split
    - Testing with DTrees --> Still yeilds 100% accuracy
"""
print("\n### CONSOLE: calling ShuffleSplit and cross_val_score()...")
from sklearn.model_selection import cross_val_score, ShuffleSplit
ssplit = ShuffleSplit(n_splits=FOLDS, test_size=TEST_SIZE, random_state=RANDOM_STATE)
scores = cross_val_score(clf, perms, labels, cv=ssplit)
print(scores.mean())
print(scores.std())

"""
### SMOTE
- This can be called prior to any sort of data separation
    - cross_val_score(), train_test_split(), KFold(), etc.
"""
print("\n### CONSOLE: SMOTE TEST...")
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
perms_res, lables_res = smote.fit_resample(perms, labels)
ssplit = ShuffleSplit(n_splits=FOLDS, test_size=0.3, random_state=0)
scores = cross_val_score(clf, perms, labels, cv=ssplit)
print(scores.mean())
print(scores.std())

"""
# Vanilla test-train split
"""
print("### CONSOLE: Vanilla Datset split...")
xTrain, xTest, yTrain, yTest = train_test_split(perms, labels, random_state=0, test_size=0.2)

### Training
t0 = time.time()
clf.fit(xTrain, yTrain)
print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time

### Testing
prediction = clf.predict(xTest)
print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time

### Metrics
confusion = confusion_matrix(yTest, prediction)
print(f"Prediction accuracy: {accuracy_score(prediction, yTest):.3f}%")
print(f"Confusion Matrix:\n{confusion}")
print("Malware")
print(f"Malware correctly identified (True Positives): {confusion[1][1]}")
print(f"Falsely classified as malicious (False Positives): {confusion[1][0]}")
print(f"Falsely classified as safe (False Negatives): {confusion[0][1]}") # --> MINIMIZE THIS VALUE
print(f"Recall: {(confusion[1][1] / sum(confusion[1])):.3f}")
print(f"Percision: {(confusion[1][1] / sum([confusion[r][1] for r in range(len(confusion))])):.3f}")
print()

"""
### Manual K-Fold Cross-Validation
- IMPROVE WITH SMOTE
- I'm pretty confident I'm not doing this right. Might have to go back to the drawing board with this.
"""
print("\n### CONSOLE: Practicing with manual K-Fold Cross-Validation")
kf = KFold(n_splits=FOLDS, random_state=RANDOM_STATE, shuffle=True) # declaring KFold object

# for i, (trainIndx, testIndx) in enumerate(kf.split(perms, labels)):
#     print(f"Iteration: {i + 1}")
#     # print(trainIndx)
#     # print(testIndx)
    
#     xTrain = [perms[i] for i in trainIndx]
#     xTest = [perms[i] for i in testIndx]
#     yTrain = [labels[i] for i in trainIndx]
#     yTest = [labels[i] for i in testIndx]

#     clf = SVC(kernel="poly", C=5, gamma='scale') # Calling within loop so that everything is reset

#     ### Training
#     t0 = time.time()
#     clf.fit(xTrain, yTrain)
#     print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time

#     ### Testing
#     prediction = clf.predict(xTest)
#     print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time

#     ### Metrics
#     confusion = confusion_matrix(yTest, prediction)
#     print(f"Prediction accuracy: {accuracy_score(prediction, yTest):.3f}%")
#     print(f"Confusion Matrix:\n{confusion}")
#     print("Malware")
#     print(f"Malware correctly identified (True Positives): {confusion[1][1]}")
#     print(f"Falsely classified as malicious (False Positives): {confusion[1][0]}")
#     print(f"Falsely classified as safe (False Negatives): {confusion[0][1]}") # --> MINIMIZE THIS VALUE
#     print(f"Recall: {(confusion[1][1] / sum(confusion[1])):.3f}")
#     print(f"Percision: {(confusion[1][1] / sum([confusion[r][1] for r in range(len(confusion))])):.3f}")
#     print()

"""
### Deep Neural Networks
"""