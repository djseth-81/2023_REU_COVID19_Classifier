"""
Author: Seth Johnson
Date: 07-07-2023
Details:
- Playground for me to mess around with individual components of the overall Models.ipynb
"""
"""
### TODO
    - GET CNN WORKING
"""
### Generic pkgs
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time
import pylab as pl
import random
from pprint import pprint
# From Scikit-Learn
from sklearn.naive_bayes import CategoricalNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import(
    accuracy_score,
    confusion_matrix,
    classification_report,
    make_scorer
)
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import(
    train_test_split, 
    KFold,
    cross_validate,
    ShuffleSplit,
    GridSearchCV
)
from imblearn.over_sampling import SMOTE
# From Tensorflow/Keras
import tensorflow as tf
import keras
from keras.layers import (
    Dense,
    Conv2D,
    Conv1D,
    MaxPool2D,
    Flatten,
    Dropout,
    BatchNormalization,
    Embedding,
    LSTM
)
from keras.preprocessing.image import ImageDataGenerator
from keras.preprocessing.text import Tokenizer
from keras.utils import pad_sequences
from keras import utils
from keras.models import Sequential
from keras import backend as K

### Static Variable Declaration
# !!! CHANGE THESE VALUES IF WE WANT TO TWEAK OUR MODELS !!!!
FOLDS = 20 # How many times our models will iterate through a dataset
RANDOM_STATE = 0 # The "entropy" of our paritioned datasets. This determines how similar one dataset is to the next.
TEST_SIZE = 0.1 # The percentage of testing data to the training data.
CSV_FILE = "2023_REU_Workspace/COVID19_APK_Data_06-2023.csv" # CSV File consisting of analyzed APK data
INT_ARR = [1, 3, 5, 10, 20, 50, 100, 1000]


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
models = {} # Dictionary to contain all performance metrics of our models.
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

def visualize(arrs,lbls=None, title=None, x_Axs=None, y_Axs=None, save=False, flip=False):
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
    width = 0.5 # Designates the width of the bar

    # Ensuring array sizes matches
    if len(arrs[0]) != len(arrs[1]):
        raise Exception(f"Array sizes do not match!\n Expected size: {len(arrs[0])}")
        return 0

    # if (lbls != None) and (len(lbls) != arrs[0]):
    #     raise Exception(f"Lables array does not match a data array!\n Expected size: {len(arrs[0])}")
    #     return 0

    if flip:
        for i, arr in enumerate(arrs):
            plt.barh(np.arange(len(arr)) + (width * i), arr, width, label=i)
        if lbls != None:
            plt.yticks(np.arange(len(lbls)), lbls) # associating indicies with xArr
    else:
        for i, arr in enumerate(arrs):
            plt.bar(np.arange(len(arr)) + (width * i), arr, width, label=i)
        if lbls != None:
            plt.xticks(np.arange(len(lbls)), lbls) # associating indicies with xArr

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
### Overridden callback class "timer" for catching epoch/total time
- do we need this?
"""
class timer(keras.callbacks.Callback):
    import time
    def __init__(self): # initalized callback
        super(timer, self).__init__() # remember inheritance from OOP

    # training methods
    def on_train_begin(self, logs=None):
        self.start_train=time.time()

    def on_train_end(self, logs=None):
        stop_train = time.time()
        tr_duration = stop_train - self.start_train
        # Calculates metrics
        tr_hours = tr_duration // 3600
        tr_minutes = (tr_duration - (tr_hours * 3600)) // 60
        tr_seconds = tr_duration - ((tr_hours * 3600) + (tr_minutes * 60))
        # Generates message of string
        msg = f"\nElapsed time: {tr_hours:.0f}:{tr_minutes:.0f}:{tr_seconds:.3f}\n"
        print(msg)
    
    # batch training methods <-- might not need this
    def on_train_batch_begin(self, batch, logs=None):
        pass
    def on_train_batch_end(self, batch, logs=None):
        pass

    # epoch methods
    def on_epoch_begin(self, epoch, logs=None):
        self.start_epoch = time.time()
    
    def on_epoch_end(self, epoch, logs=None):
        stop_epoch = time.time()
        epoch_duration = stop_epoch - self.start_epoch
        msg = f"Epoch {epoch + 1} trained for {epoch_duration} seconds"
        print(msg)

    # prediction methods <-- this might be useful in the long run during CrossVal
    def on_predict_begin(self, logs=None):
        pass

    def on_predict_end(self, logs=None):
        pass

"""
### UDF to calculate metrics for our Neural Network
- not confident we need these anymore
"""
# This genuinely confuses me, documentation states that they depriciated Recall and precision from keras.metrics, but I can still use it. 
# Tensorflow docs say that I can call all those, plus F1Score, but I cannot call F1Score at all, no matter what I try
# Trying a custom set of functions to handle getting metrics better, guided by Stack Overflow because I'm uncreative and cannot figure out anything at all
from keras import backend as K
def recallCalc(train, test):
    true_positives = K.sum(K.round(K.clip(train * test, 0, 1)))
    possible_positives = K.sum(K.round(K.clip(train, 0, 1)))
    recall = true_positives / (possible_positives + K.epsilon())
    return recall

def precisionCalc(train, test):
    true_positives = K.sum(K.round(K.clip(train * test, 0, 1)))
    predicted_positives = K.sum(K.round(K.clip(test, 0, 1)))
    precision = true_positives / (predicted_positives + K.epsilon())
    return precision

def f1Calc(train, test):
    precision = precisionCalc(train, test)
    recall = recallCalc(train, test)
    return 2 * ((precision*recall) / (precision + recall + K.epsilon()))

"""
### NOTE
- classification_report is heckin gorgeous
- pass output_dict=True to function if I want to return the dictionary per instance!
- EXAMPLE: print(classification_report(np.argmax(yTest, axis=1), np.argmax(prediction, axis=1)))
"""
def recordClassifier(labels, prediction, clfName):
    OUTPUT_FILE = "2023_REU_Workspace/ClassifierMetrics.txt"
    
    operand = "a+" if os.path.isfile(OUTPUT_FILE) else "w+"
        
    with open(OUTPUT_FILE, operand) as outFile:
        outFile.write(f"###### {clfName} ######\n")
        outFile.write(f"Accuracy: {(accuracy_score(prediction, labels) * 100):.2f}%\n")
        outFile.write("Classification Report: \n")
        outFile.write(classification_report(labels, prediction)+"\n\n")
    
    return 1

"""
### NOTE
- The following is used to make classification_report compatible with cross_validate()
- I could very well just pass scoring=[accuracy, precision, recall] to cross_validate() to then results and calculate f1 score
"""
from sklearn.metrics import make_scorer
test = []
prediction = []
def buildClassificationReport (yTest, yPred):
    test.clear()
    prediction.clear()
    test.extend(yTest)
    prediction.extend(yPred)
    return accuracy_score(yTest, yPred)

"""
########################################################### PREPROCESSING ##########################################################################
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

apks = apkData["APK File"].values # Pulling APK files to correlate labels
avRanks = apkData["AV Rank"].values # pulls AV Rank from csv DF
labels = [1 if i > 0 else 0 for i in avRanks] # builds an array of malware classification based off avRank. <-- This will be our labels

perms = [apkData.loc[i].drop((i for i in keys)).values for i in range(len(apkData))] # Genereating features array that drops first 6 columns to include the total permissions requested, followed by the PermSpread


# verifyPreprocessing() # Verifying that everything went smoothly

print("### CONSOLE: Preprocessing complete...")

"""
### PARAMETER DECLARATION
- Modify this value if we wanna change how many iterations our models go through
    - this will change the size of masterTrain and masterTest arrays, hence changing how many times each model iterates through these folds
"""
FOLDS = 20
RANDOM_STATE = 0
TEST_SIZE = 0.1
INT_ARR = [1, 3, 5, 10, 20, 50, 100, 1000]

"""
### Sklearn ShuffleSplit module
- https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.ShuffleSplit.html
- cross_validate(): https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.cross_validate.html#sklearn.model_selection.cross_validate
- compare with the current manual split
"""
print("### CONSOLE: Prepping K-Fold C-V...")
ssplit = ShuffleSplit(n_splits=FOLDS, test_size=TEST_SIZE, random_state=RANDOM_STATE)

"""
### SMOTE
- https://imbalanced-learn.org/stable/references/generated/imblearn.over_sampling.SMOTE.html
- This can be called prior to any sort of data separation
"""
print("### CONSOLE: prepping SMOTE...")
smote = SMOTE(random_state=RANDOM_STATE)
permsSMOTE, labelsSMOTE = smote.fit_resample(perms, labels)

print("### CONSOLE: Skcikit-learn prep complete.")

"""
### Site for Tensorflow reference: https://www.tensorflow.org/guide/distributed_training
"""

"""
### Can we use the GPU?
"""
if tf.test.gpu_device_name():
    print(f'GPU installed. Good Job!\nGPU Device: {tf.test.gpu_device_name()}\n')
else:
    print("No GPU found that can run TF.\n")


"""
### data prep with SkLearn
"""
xTrain, xTest, yTrain, yTest = train_test_split(perms, labels, random_state=RANDOM_STATE, test_size=TEST_SIZE)
# xTrain, xTest, yTrain, yTest = train_test_split(permsSMOTE, labelsSMOTE, random_state=RANDOM_STATE, test_size=TEST_SIZE)

# Converting to NumPy float64. Tensorflow hates int64
xTrain = np.asarray(xTrain).astype('float32')
xTest = np.asarray(xTest).astype('float32')
yTrain = np.asarray(yTrain).astype('float32')
yTest = np.asarray(yTest).astype('float32')

NUM_CATS = 2 # The quantity of categories we are going to organize our APK files into. 0 for benign, 1 for malware: S({0, 1}) = 2

yTrain = keras.utils.to_categorical(yTrain, NUM_CATS)
yTest = keras.utils.to_categorical(yTest, NUM_CATS)

print("### CONSOLE: Neural Network prep compete.")

"""
########################################################### Modeling ##########################################################################
"""
# normalizing since they're working with TPR value
xTrain = xTrain / xTrain.max()
xTrain = xTrain / xTrain.max()

print(f"Traning data\n x: {xTrain.shape}, y: {yTrain.shape}")
print(f"Traning data\n x: {xTest.shape}, y: {yTest.shape} ")
# Reshapng my features dataset for convolution layers
"""
# NOTE
- normalize features before re-shaping
- ignore total number of permissions for this instance
- Try reshaping on a PER APK BASIS
"""

# reshaping our dataset
xTrain = xTrain.reshape(-1, xTrain.shape[0], xTrain.shape[1], 1)
xTest = xTest.reshape(-1, xTest.shape[0], xTest.shape[1], 1)

print(xTrain.shape)
print(xTest.shape)

yTrain = yTrain.reshape(-1, yTrain.shape[0], 2)
yTest = yTest.reshape(-1, yTest.shape[0], 2)

print(yTrain.shape)
print(yTest.shape)

### Building layers
model = keras.models.Sequential()

# Convolutional layer
model.add(Conv2D(50, (3, 3), strides=1, padding="same", activation="relu", input_shape=(xTrain.shape[1], xTrain.shape[2], 1)))
# Batch Normalization layer
model.add(BatchNormalization())
# Pooling layer
model.add(MaxPool2D((2, 2), strides=2, padding="same"))

# Convolutional layer
model.add(Conv2D(25, (3, 3), strides=1, padding="same", activation="relu"))
# Enabling a Droput
model.add(Dropout(0.2))
# Batch Normalization layer
model.add(BatchNormalization())
# Pooling layer
model.add(MaxPool2D((2, 2), strides=2, padding="same"))

# Convolutional layer
model.add(Conv2D(10, (3, 3), strides=1, padding="same", activation="relu"))
model.add(BatchNormalization())
model.add(MaxPool2D((2, 2), strides=2, padding="same"))

# Convolutional layer
model.add(Conv2D(5, (3, 3), strides=1, padding="same", activation="relu"))
model.add(BatchNormalization())
model.add(MaxPool2D((2, 2), strides=1, padding="same"))
model.add(Flatten())

# input
model.add(Dense(units=xTrain.shape[1], activation="relu"))
# Hidden Layers
model.add(Dense(units=xTrain.shape[1], activation="relu")) # wonder if changing the units value dos anything...
# Output
model.add(Dense(units=NUM_CATS, activation="softmax"))

# Displaying model summary
model.summary()

### Compiling, fitting
model.compile(loss='binary_crossentropy', metrics=['accuracy'])
models.update(
    { "CNN": model.fit(
    xTrain, yTrain, 
    epochs=20, 
    verbose=0,
    validation_data=(xTest, yTest),
    callbacks=[timer()]
)})

### Displaying results
# pprint(history.history)

fig, axis = plt.subplots(2, 2, figsize=(20,15))
for key, value in models.items():
    axis[0,0].plot(value.history["loss"], label=key)
    axis[0,0].set_title("loss")
    axis[0,1].plot(value.history["accuracy"], label=key)
    axis[0,1].set_title("accuracy")
    axis[1,0].plot(value.history["val_loss"], label=key)
    axis[1,0].set_title("val_loss")
    axis[1,1].plot(value.history["val_accuracy"], label=key)
    axis[1,1].set_title("val_accuracy")
    plt.legend()
    plt.show()

print("### CONSOLE: Analysis of Connected Neural Network completed.")