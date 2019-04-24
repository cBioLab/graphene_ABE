/*
 * 実行方法はcheck.shを参照
 * 入力された(前処理済み)データを用いてロジスティック回帰を行い、
 * parameterを出力するプログラム。
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <random>
#include <cassert>
#include <algorithm>
#include <chrono>

using namespace std;

double getSigmoid(vector<double> x, vector<double> theta, int column){
  double param = 0.0;

  for(int i=0; i<column; i++){
    param -= theta[i] * x[i];

    /*
    if(i==0)
    cout << "-" << theta[i] << "*" << x[i] << " - ";
    else if(i==column-1)
    cout << theta[i] << "*" << x[i] << " = ";
    else
    cout << theta[i] << "*" << x[i] << " - ";
    */
  }
  //cout << param << endl;

  return 1 / (1 + exp(param));
}


int main(int argc, char* argv[]){
  string trainFile, thetaFile;
  int trainIndex, trainColumn;
  vector<double> theta, y, diff;
  vector< vector<double> > x;
  double LLF, sum, sigmoid;

  // constant number.
  int lambda = 1;
  int iteration = 100;
  double rate = 0.01;
  
  if(argc != 3){
    cout << "Error: input file as follows..." << endl;
    cout << "./LogisticRegression [train data file] [result file name]." << endl;
    return 1;
  }

  trainFile = argv[1];
  thetaFile = argv[2];
  cout << "train file: " << trainFile << ", result file(tmp): " << thetaFile << endl;
  
  ifstream traindata(trainFile.c_str(), ios::in);
  if(!traindata){
    cerr << "File can not open..." << endl;
    exit(1);
  }
  
  traindata >> trainIndex;
  traindata >> trainColumn;

  cout << "train data(index): " << trainIndex << ", train data(column, include class): " << trainColumn << endl;
  
  // get dataset.
  y.resize(trainIndex);
  x.resize(trainIndex);
  for(int i=0; i<trainIndex; i++){
    x[i].resize(trainColumn);
  }

  for(int i=0; i<trainIndex; i++){
    for(int j=0; j<trainColumn; j++){
      if(j==0){
	traindata >> y[i];
	x[i][j] = 1;
	//cout << "y[" << i << "]: " << y[i] << "\nx[" << i << "]: ";
      }
      else{
	traindata >> x[i][j];
      }

      //cout << x[i][j] << ", ";
    }
    //cout << endl;
  }
  traindata.close();
  
  
  // initialize theta.
  theta.resize(trainColumn);
  random_device random;
  mt19937 mt(random());
  uniform_real_distribution<> rand(-0.1, 0.1);
  for(int i=0; i<trainColumn; i++){
    //theta[i] = rand(mt);
    theta[i] = 0.0;
  }

  // update theta.
  cout << "start calculation theta..." << endl;
  auto start = chrono::system_clock::now();
  
  for(int itr=0; itr<iteration; itr++){
    // for each theta.
    for(int j=0; j<trainColumn; j++){
      // initialization.
      LLF = 0.0;
      sum = 0.0;
      diff.resize(trainIndex);
      
      for(int i=0; i<trainIndex; i++){
	if(j == 0){
	  sigmoid = getSigmoid(x[i], theta, trainColumn);
	  //cout << "sigmoid[" << i << "]: " << sigmoid << endl;

	  diff[i] = sigmoid - y[i];
	  //cout << "sigmoid - y[" << i << "] - sigmoid = " << sigmoid << "- " << y[i] << " = " << diff[i] << endl;
	}
	
	sum += diff[i] * x[i][j];
	//cout << sum << endl;
      }
      
      // calculate differentiated Log-likelihood function(LLF, include Regularization item).
      LLF = (lambda * theta[j] + sum) / trainIndex;
      
      // gradient descent method.
      theta[j] = theta[j] - rate * LLF;
      //cout << theta[j] << endl;
    }
  }

  auto end = chrono::system_clock::now();
  auto time = end - start;
  cout << "LR scheme time: "
       << chrono::duration_cast<chrono::microseconds>(time).count() << "[microsec]" << endl;

  cout << "end calculation theta..." << endl;
  
  // save theta in file.
  ofstream ofs(thetaFile.c_str(), ios::out);
  for(int i=0; i<trainColumn; i++){
    //cout << "theta[" << i << "]: " << theta[i] << endl;

    ofs << theta[i];
    ofs << "\n";
  }
  ofs.close();
  cout << "save theta..." << endl;
  
  return 0;
}
