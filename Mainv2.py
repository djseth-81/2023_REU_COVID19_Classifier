"""
### Main ###
Author: Seth Johnson
Date 07-14-2023
"""
"""
########################################## Package Handling #########################################
"""
# From Scikit-Learn
from imblearn.over_sampling import SMOTE
from sklearn.naive_bayes import CategoricalNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import(
    accuracy_score,
    classification_report,
    make_scorer,
    precision_recall_fscore_support
)
from sklearn.model_selection import(
    train_test_split, 
    StratifiedKFold,
    cross_validate,
    ShuffleSplit
)
# From Tensorflow/Keras
import tensorflow as tf
import keras
from keras.layers import Dense
from keras.preprocessing.image import ImageDataGenerator # no use
from keras.preprocessing.text import Tokenizer # no use
from keras.utils import pad_sequences # no use
from keras import utils
from keras.models import Sequential
# Custom modules 
from CSVHandler import *
from DatasetStatistics import *

"""
########################################## Variable declaration #########################################
"""
apkData = -1 # DataFrame of all APK data harvested from APKScanner.py
apks = -1 # NumPy array that lists apk file hashes
avRanks = -1 # NumPy Array that lists the AV Ranking for each file
permKeys = [] # Key values for the permissions requested by a given APK file. This is for reference for our perms array
keys = [] # Lables of CSV data that is NOT the permissions requested by a given APK file
perms = -1 # "Features". NumPy array consisting of arrays which hold the permission attributes for a given element in apks @ the same index. First two elements indicate AV Rank, and Total Permissions Requested. Subsequent elements are a binary representation of the types of permissions the apk file requests.
labels = [] # "Labels". Array of arrays of 0s(benign) or 1s(malicious). Matches index values with apks and avRanks to indicate if apk file is malicious
permsSMOTE = [] # Array of the features treated with SMOTE
labelsSMOTE = [] # Array of the lables treated with SMOTE
xTrain = -1 # Array consisting training features. This is passed into fit() methods
xTest = -1 # Array consisting of testing features. Predictions will use this variable.
yTrain = -1 # Array consisting of training labels. Pass into fit() methods for supervised learning.
yTest = -1 # Array consisting of testing labels. This assists with metrics, and backpropogation
clf = -1 # Classifier variable to assign to different models
prediction = -1 # Array consisting of the results of a classifier's prediction call
ssplit = -1 # Cross-Validation object created by sklearn's ShuffleSplit(). Passed as a CV parameter for cross_val_score()
scores = -1 # Array consisting of metrics from sklearn's cross_val_score()
# visual aids
t0 = 0 # float value for recording a model's performance duration

"""
### OPTIMIZATION PARAMETER DECLARATION
- Modify this value if we wanna change how many iterations our models go through
    - this will change the size of masterTrain and masterTest arrays, hence changing how many times each model iterates through these folds
"""
NUM_CATS = 2 # The quantity of categories we are going to organize our APK files into. 0 for benign, 1 for malware: S({0, 1}) = 2
FOLDS = 20
RANDOM_STATE = 0
TEST_SIZE = 0.1
CSV_FILE = "2023_REU_Workspace/COVID19_APK_Data_06-2023.csv" # CSV File consisting of analyzed APK data
OUTPUT_FILE = "2023_REU_Workspace/ClassifierReport_noTPR.txt"

"""
########################################## UDF Declaration #########################################
"""
# Used to make classification_report compatible with cross_validate()
def buildClassificationReport (yTest, yPred):
    test.extend(yTest)
    prediction.extend(yPred)
    return accuracy_score(yTest, yPred)

# Used to record metrics of an instance of a classifier
# pass output_dict=True to function if I want to return the dictionary per instance!
def recordClassifier(labels, prediction, clfName):
    # operand = "a+" if os.path.isfile(OUTPUT_FILE) else "w+"
        
    with open(OUTPUT_FILE, "a+") as outFile:
        outFile.write(f"### {clfName}\n")
        outFile.write(f"Accuracy: {(accuracy_score(prediction, labels) * 100):.2f}%\n")
        outFile.write("Classification Report: \n")
        outFile.write(classification_report(labels, prediction)+"\n\n")
    
    return 1

# Function to define and compile our Deep Neural Network model
def buildDNN(NUM_CATS, xTrain):
    ### Clearing Tensorflow memory before building new model
    tf.keras.backend.clear_session()

    ### Building layers
    model = keras.models.Sequential()
    # input
    model.add(Dense(units=xTrain.shape[0], activation="relu", input_shape=(xTrain.shape[1],)))
    # Hidden Layers
    model.add(Dense(units=xTrain.shape[0], activation="relu")) # wonder if changing the units value dos anything...
    # Output
    model.add(Dense(units=NUM_CATS, activation="softmax"))

    ### Compiling model
    # Changed loss from categorical to binary, given w have a binary output
    model.compile(loss='binary_crossentropy', metrics=["accuracy"])
    return model

# Calls buildDNN() to create a model, iterates through a KFold Cross-Validation loop, then writes it to OUT_FILE
def dnnKFold(features, lables, imbalanced=False): 
    results = { # where to store my results temporarily
        "benign": {
            "fscore": [],
            "precision": [],
            "recall": [],
            "support": [],
        },
        "malicious": {
            "fscore": [],
            "precision": [],
            "support": [],
            "recall": [],
        },
        "accuracy": [],
    }
    cats = [i for i in results.keys()][:2] # b/c I'm lazy man...
    kf = StratifiedKFold(n_splits=FOLDS, random_state=RANDOM_STATE, shuffle=True) # initiating the kfold object
    for num, (trainIndx, testIndx) in enumerate(kf.split(features, labels)):
        print(f"Fold: {num + 1}")
        
        xTrain = [features[i] for i in trainIndx]
        xTest =  [features[i] for i in testIndx]
        yTrain = [labels[i] for i in trainIndx]
        yTest =  [labels[i] for i in testIndx]

        xTrain = np.asarray(xTrain).astype('float64')
        xTest = np.asarray(xTest).astype('float64')
        yTrain = np.asarray(yTrain).astype('float64')
        yTest = np.asarray(yTest).astype('float64')
        
        if imbalanced:
            xTrain_SMOTE, yTrain_SMOTE = smote.fit_resample(xTrain, yTrain)

        yTrain = keras.utils.to_categorical(yTrain, NUM_CATS)
        yTest = keras.utils.to_categorical(yTest, NUM_CATS)

        model = buildDNN(NUM_CATS, xTrain)

        # Displaying model summary
        # model.summary()
        
        model.fit(
            xTrain, yTrain, 
            epochs=20,
            verbose=0,
            validation_data=(xTest, yTest),
            callbacks=[timer()]
        )

        prediction = np.argmax(model.predict(xTest), axis=1)
        results["accuracy"].append(accuracy_score(prediction, np.argmax(yTest, axis=1)))

        metrics = precision_recall_fscore_support(np.argmax(yTest, axis=1), prediction)

        for i, key in enumerate(cats):
            results[key]["precision"].append(metrics[0][i])
            results[key]["recall"].append(metrics[1][i])
            results[key]["fscore"].append(metrics[2][i])
            results[key]["support"].append(metrics[3][i])
            # pprint(results)

    with open(OUTPUT_FILE, "a+") as outFile:
        outFile.write(f"###### Connected Neural Network ######\n")
        outFile.write(f"Accuracy: {(np.mean(results['accuracy']) * 100):.2f}%\n")
        outFile.write("Classification Report: \n")
        outFile.write(f"{'precision':>23}{'recall':>10}{'f1-score':>10}{'support':>10}\n") # THIS IS FOR THE LABELS
        outFile.write("\n")
        outFile.write(f"{0:>12}{np.mean(results['benign']['precision']):>11.2f}{np.mean(results['benign']['recall']):>10.2f}{np.mean(results['benign']['fscore']):>10.2f}{np.floor(np.mean(results['benign']['support'])):>10.0f}\n")
        outFile.write(f"{1:>12}{np.mean(results['malicious']['precision']):>11.2f}{np.mean(results['malicious']['recall']):>10.2f}{np.mean(results['malicious']['fscore']):>10.2f}{np.floor(np.mean(results['malicious']['support'])):>10.0f}\n")
        outFile.write("\n")
        outFile.write(f"{'accuracy':>12}{np.mean(results['accuracy']):>31.2f}{xTest.shape[0]:>10.0f}\n")

    return 1

"""
########################################## Model Prep #########################################
"""

### Preprocessing
apkData, keys, permKeys, apks, avRanks, perms, labels = preprocessing(CSV_FILE)
perms = [i[1:] for i in perms]
permKeys = permKeys[1:]
print(len(perms[0]))
print(len(permKeys))
print(perms[0])
print(permKeys)
# verifyPreprocessing()

### Visualize data
# preModelingVisuals(permKeys, apks, perms, labels)
displayStats(apks, labels)

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
    - But not for KFold, for some reason?
"""
print("### CONSOLE: prepping SMOTE...")

smote = SMOTE(random_state=RANDOM_STATE,sampling_strategy={1: 270})
permsSMOTE, labelsSMOTE = smote.fit_resample(perms, labels)

"""
### Can we use the GPU?
"""
if tf.test.gpu_device_name():
    print(f'GPU installed. Good Job!\nGPU Device: {tf.test.gpu_device_name()}\n')
else:
    print("No GPU found that can run TF.\n")

"""
### Custom callback class "timer" for catching epoch/total time
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

print("### CONSOLE: Prep successful.")


"""
########################################## Control Group #########################################
"""
print("\n### CONSOLE: Starting control group...\n")

with open(OUTPUT_FILE, "a+") as outFile:
    outFile.write(f"############################### CONTROL GROUP ###############################\n")

### Splitting data
xTrain, xTest, yTrain, yTest = train_test_split(perms, labels, random_state=RANDOM_STATE, test_size=TEST_SIZE)
# Converting to NumPy float32. Tensorflow hates int64
xTrain = np.asarray(xTrain).astype('float32')
xTest = np.asarray(xTest).astype('float32')
yTrain = np.asarray(yTrain).astype('float32')
yTest = np.asarray(yTest).astype('float32')

print("### CONSOLE: Executing CatNB...")
clf = CategoricalNB(min_categories=len(perms))

# t0 = time.time()
clf.fit(xTrain, yTrain) # Train
# print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time
# t0 = time.time()
prediction = clf.predict(xTest) # Predicting
# print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time
# print(f"CNB accuracy: {(accuracy_score(prediction, yTest) * 100):.2f}%")
recordClassifier(yTest, prediction, "Classical Naive-Bayes")

print("### CONSOLE: Executing Support Vector Machines...")
clf = SVC()

# t0 = time.time()
clf.fit(xTrain, yTrain) # Train
# print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time
# t0 = time.time()
prediction = clf.predict(xTest) # Predicting
# print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time
# print(f"CNB accuracy: {(accuracy_score(prediction, yTest) * 100):.2f}%")
recordClassifier(yTest, prediction, "Support Vector Machines")

print("### CONSOLE: Executing Decision Trees...")
clf = DecisionTreeClassifier(splitter="random")

# t0 = time.time()
clf.fit(xTrain, yTrain) # Train
# print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time
# t0 = time.time()
prediction = clf.predict(xTest) # Predicting
# print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time
# print(f"CNB accuracy: {(accuracy_score(prediction, yTest) * 100):.2f}%")
recordClassifier(yTest, prediction, "Decision Trees")

print("### CONSOLE: Executing Deep Neural Network...")

model = buildDNN(NUM_CATS, xTrain)
# Displaying model summary
# model.summary()

yTrain = keras.utils.to_categorical(yTrain, NUM_CATS)
yTest = keras.utils.to_categorical(yTest, NUM_CATS)

### fitting
model.fit(
    xTrain, yTrain, 
    epochs=20, 
    verbose=0,
    validation_data=(xTest, yTest),
    callbacks=[timer()]
)

prediction = model.predict(xTest)
recordClassifier(np.argmax(yTest, axis=1), np.argmax(prediction, axis=1), "Connected Neural Network")

print("### CONSOLE: Control group complete.")

"""
########################################## SMOTE #########################################
"""
print("\n### CONSOLE: Starting SMOTE group...\n")

with open(OUTPUT_FILE, "a+") as outFile:
    outFile.write(f"############################### TRAIN/TEST SPLIT WITH SMOTE ###############################\n")


xTrain, xTest, yTrain, yTest = train_test_split(permsSMOTE, labelsSMOTE, random_state=RANDOM_STATE, test_size=TEST_SIZE)
# Converting to NumPy float32. Tensorflow hates int64
xTrain = np.asarray(xTrain).astype('float32')
xTest = np.asarray(xTest).astype('float32')
yTrain = np.asarray(yTrain).astype('float32')
yTest = np.asarray(yTest).astype('float32')

print("### CONSOLE: Executing CatNB...")
clf = CategoricalNB(min_categories=len(perms))

# t0 = time.time()
clf.fit(xTrain, yTrain) # Train
# print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time
# t0 = time.time()
prediction = clf.predict(xTest) # Predicting
# print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time
# print(f"CNB accuracy: {(accuracy_score(prediction, yTest) * 100):.2f}%")
recordClassifier(yTest, prediction, "Classical Naive-Bayes")

print("### CONSOLE: Executing Support Vector Machines...")
clf = SVC()

# t0 = time.time()
clf.fit(xTrain, yTrain) # Train
# print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time
# t0 = time.time()
prediction = clf.predict(xTest) # Predicting
# print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time
# print(f"CNB accuracy: {(accuracy_score(prediction, yTest) * 100):.2f}%")
recordClassifier(yTest, prediction, "Support Vector Machines")

print("### CONSOLE: Executing Decision Trees...")
clf = DecisionTreeClassifier(splitter="random")

# t0 = time.time()
clf.fit(xTrain, yTrain) # Train
# print(f"Training time: {(time.time() - t0):.3f} s") # Mark training time
# t0 = time.time()
prediction = clf.predict(xTest) # Predicting
# print(f"Prediction Time: {(time.time() - t0):.3f} s") # marking prediction time
# print(f"CNB accuracy: {(accuracy_score(prediction, yTest) * 100):.2f}%")
recordClassifier(yTest, prediction, "Decision Trees")

print("### CONSOLE: Executing Deep Neural Network...")

model = buildDNN(NUM_CATS, xTrain)
# Displaying model summary
# model.summary()

yTrain = keras.utils.to_categorical(yTrain, NUM_CATS)
yTest = keras.utils.to_categorical(yTest, NUM_CATS)

### fitting
model.fit(
    xTrain, yTrain, 
    epochs=20, 
    verbose=0,
    validation_data=(xTest, yTest),
    callbacks=[timer()]
)

prediction = model.predict(xTest)
recordClassifier(np.argmax(yTest, axis=1), np.argmax(prediction, axis=1), "Connected Neural Network")

print("### CONSOLE: Processing with SMOTE complete.")

"""
########################################## K-Fold Cross-Validation #########################################
"""
print("\n### CONSOLE: Starting Cross-Validation group...\n")

with open(OUTPUT_FILE, "a+") as outFile:
    outFile.write(f"############################### CROSS-VALIDATION GROUP ###############################\n")

print("### CONSOLE: Executing CNB...")
clf = CategoricalNB(min_categories=len(perms))

test = []
prediction = []
scores = cross_validate(clf, perms, labels, cv=ssplit, scoring=make_scorer(buildClassificationReport))
recordClassifier(test, prediction, "Classical Naive-Bayes")

print("### CONSOLE: Executing Support Vector Machines...")
clf = SVC()

test = []
prediction = []
scores = cross_validate(clf, perms, labels, cv=ssplit, scoring=make_scorer(buildClassificationReport))
recordClassifier(test, prediction, "Support Vector MachineS")

print("### CONSOLE: Executing Decision Trees...")
clf = DecisionTreeClassifier(splitter="random")

test = []
prediction = []
scores = cross_validate(clf, perms, labels, cv=ssplit, scoring=make_scorer(buildClassificationReport))
recordClassifier(test, prediction, "Decision Trees")

print("### CONSOLE: Executing Deep Neural Network...")

dnnKFold(perms, labels)

print("\n### CONSOLE: Cross-Validation complete.\n")

"""
########################################## K-Fold Cross-Validation with SMOTE #########################################
"""
print("\n### CONSOLE: Starting CV with SMOTE group...\n")

with open(OUTPUT_FILE, "a+") as outFile:
    outFile.write(f"############################### CROSS-VALIDATION WITH SMOTE ###############################\n")


print("### CONSOLE: Executing CNB...")
clf = CategoricalNB(min_categories=len(perms))

test = []
prediction = []
scores = cross_validate(clf, permsSMOTE, labelsSMOTE, cv=ssplit, scoring=make_scorer(buildClassificationReport))
recordClassifier(test, prediction, "Classical Naive-Bayes")

print("### CONSOLE: Executing Support Vector Machines...")
clf = SVC()

test = []
prediction = []
scores = cross_validate(clf, permsSMOTE, labelsSMOTE, cv=ssplit, scoring=make_scorer(buildClassificationReport))
recordClassifier(test, prediction, "Support Vector Machines")

print("### CONSOLE: Executing Decision Trees...")
clf = DecisionTreeClassifier(splitter="random")

test = []
prediction = []
scores = cross_validate(clf, permsSMOTE, labelsSMOTE, cv=ssplit, scoring=make_scorer(buildClassificationReport))
recordClassifier(test, prediction, "Decision Trees")

print("### CONSOLE: Executing Deep Neural Network...")

dnnKFold(perms, labels, imbalanced=True)

print("\n### CONSOLE: CV with SMOTE complete.\n")