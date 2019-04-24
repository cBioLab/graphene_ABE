#!/usr/bin/python
# -*- coding: utf-8 -*-

# USING PYTHON 2.7.12
# ref: https://ohke.hateblo.jp/entry/2017/08/11/230000

# *** PROGRAM ***
# 1. split BreastCancerWisconsin.csv -> train-BCW.data, test-BCW.data.
# 2. LR using sklearn, get THETA(LRtheta-BCWpy.data).
# 3. get accuracy using sklern(just for reference).

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

original_df = pd.read_csv("BreastCancerWisconsin.csv")
#print("original BCW shape: {}".format(original_df.shape))

original_df.drop("Unnamed: 32", axis=1, inplace=True)
print("original BCW shape: {}".format(original_df.shape))
print("*** diagnosis value(B: benign(良性), M: malignant(悪性)) ***")
print(original_df.diagnosis.value_counts())

# 目的変数y、説明変数Xの抽出
y = original_df.diagnosis.apply(lambda d: 1 if d == 'M' else 0)
X = original_df.ix[:, 'radius_mean':]

# split data.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2) # random_state=0を指定すると初期シードが固定される。

# 標準化
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ロジスティック回帰分析
LR = LogisticRegression(max_iter=100, solver='liblinear')
LR.fit(X_train_scaled, y_train)
#LR.fit(X_train, y_train)


# get accuracy using sklern(just for reference).
print("Acuuracy(for reference): {}".format(LR.score(X_test_scaled, y_test)))


# save theta.
theta = np.append(LR.intercept_, LR.coef_)
np.savetxt("LRtheta-BCWpython.data", theta, fmt='%.8f')
print("save theta...")
#print(theta)


# save train-BCW.data, test-BCW.data.
traindata = np.insert(X_train_scaled, 0, y_train, axis=1)
trainsize = np.array([traindata.shape[0], traindata.shape[1]]) #行, 列
print "train size: " + str(trainsize)

with open("train-BCW.data", 'w') as f:
    np.savetxt(f, trainsize, fmt='%.i')
    np.savetxt(f, traindata, fmt='%.8f')
print("save traindata...")
    
testdata = np.insert(X_test_scaled, 0, y_test, axis=1)
testsize = np.array([testdata.shape[0], testdata.shape[1]]) #行, 列

with open("test-BCW.data", 'w') as f:
    #np.savetxt(f, testsize, fmt='%.i')
    np.savetxt(f, testdata, fmt='%.8f')
print("save testdata...")
