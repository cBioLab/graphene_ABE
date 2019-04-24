#!/usr/bin/python
# -*- coding: utf-8 -*-

# USING PYTHON 2.7.12

import sys
import numpy as np
from sklearn import metrics
from matplotlib import pyplot

def sigmoid(theta, data):
    u = theta.dot(data)
    return 1/(1 + np.exp((-1)*u))
                                                        
def calcAUC(theta, data):
    print "Start calculation AUC..."
    y_test, X_test = np.hsplit(testdata, [1])
    print "testdata(y) size: " + str(y_test.shape)
    print "testdata(X) size: " + str(X_test.shape)

    # preparation.
    N = data.shape[0]
    X_test = np.insert(X_test, 0, 1, axis=1)
    prethres = np.zeros(N)
    TPR = np.zeros(N)
    FPR = np.zeros(N)
    
    for i in range(N):
        prethres[i] = sigmoid(theta, X_test[i])
    prethres.sort()
    #print(prethres)

    # calculation TPR, FPR.
    maxAccuracy = 0.0
    for i in range(N):
        TP = FP = FN = TN = 0
        thres = prethres[i]

        for j in range(N):
            prov = sigmoid(theta, X_test[j])
        
            if(y_test[j]==1):
                if prov>thres:
                    TP += 1
                else:
                    FN += 1
            else:
                if prov>thres:
                    FP += 1
                else:
                    TN += 1
                    
        #print('TP(1 -> 1): %d, FN(1 -> 0): %d, FP(0 -> 1): %d,TN(0 -> 0): %d' % (TP, FN, FP, TN))
        TPR[i] = TP/(TP + FN + 0.0)#真陽性率(縦軸)
        FPR[i] = FP/(FP + TN + 0.0)#偽陽性率(横軸)
        
        accuracy = (TP+TN)*100.0 / N;
        if (accuracy>maxAccuracy):
            maxAccuracy = accuracy
            maxThres = thres

    print "Max accuracy = " + str(maxAccuracy) + ", when thres = " + str(maxThres)
    print "AUC: " + str(metrics.auc(FPR, TPR))

    #pyplot.plot(FPR, TPR)
    #pyplot.show()

    return str(maxAccuracy), str(metrics.auc(FPR, TPR))
    
if __name__ == '__main__':
    argv = sys.argv
    argc = len(argv)

    if argc!=3:
        print "Error: python analysis.py [theta_filename] [testdata]."
        quit()

    CthetaFile = argv[1]
    testFile = argv[2]

    Ctheta = np.loadtxt(CthetaFile, delimiter="\n")
    testdata = np.loadtxt(testFile, delimiter=" ")
    print "*** GET FILE !! ***"
    print "theta(c++) size: " + str(Ctheta.shape)
    print "testdata size: " + str(testdata.shape) + "\n"

    accuracy, AUC = calcAUC(Ctheta, testdata)

    #text = accuracy + ", " + AUC + "\n"
    #with open("accuracy.data", 'a') as f:
    #f.write(text)
                    
