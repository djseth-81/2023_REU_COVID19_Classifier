# 2023_REU_COVID19_Classifier
Repository for the work done on "Comparing Classifiers" for the 2023 REU Summer Session (#2308741)

# Project Overview
This repository contains Python scripts for processing APK data to train and test 4 different machine learning models:
- Support Vector Machine
- Categorical Naive-Bayes
- Decision Tree
- Connected Neural Network

They are trained under the following conditions:
- Train/test split
- KFold Cross-Validation
Those are then re-ran with a re-processed dataset using the Synthetic Minority Oversampling Technique (SMOTE).

This repository containts results files of the performance of the 4 classifiers under the various training schemes
Graphs are also included to visualize some characteristics about the collection of APK files we processed for our research.
