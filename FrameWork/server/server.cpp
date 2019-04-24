#include "SSLserver.hpp"
#include "common.h"
#include "json11.hpp"

#include <algorithm>
#include <chrono>

//for file search.
#include <bits/stdc++.h>
#include <sys/stat.h>
#include <dirent.h>

//#define TIME_MEASURING

const int PORT = 54345;
const int BUFSIZE = 16384;
char ENDMARK[] = "*** END OF MESSAGE ***";
char OK_RESPONSE[] = "OK";
char END_RESPONSE[] = "END";
static int s_server_session_id_context = 1;
static string timeFile = "exec_time.log";

using namespace oabe;

// 配列出力用
template <class T>ostream &operator<<(ostream &o,const vector<T>&v)
{o<<"{";for(int i=0;i<(int)v.size();i++)o<<(i>0?", ":"")<<v[i];o<<"}";return o;}


void ssl_write(SSL *ssl, char *character, int size){
  int r = SSL_write(ssl, character, size);

  if(SSL_get_error(ssl, r) != 0)
    berr_exit("SSL write problem...");

  return;
}

void string_to_charArray(char *charArray, int size, string message){
  initialized_char(charArray, size);

  for(int i=0; i<int(message.size()); i++)
    charArray[i] = message[i];

  return;
}

string getJSON(SSL *ssl, int s){
  char get_char[BUFSIZE];
  int r, flag = 0;
  string jString = "";

  while(flag == 0){
    initialized_char(get_char, BUFSIZE);
    
    // データを読み取る。
    r = SSL_read(ssl, get_char, BUFSIZE);

    switch(SSL_get_error(ssl, r))
      {
      case SSL_ERROR_NONE:
	if(string(get_char) == string(ENDMARK)){
	  flag = 1;
	  ssl_write(ssl, END_RESPONSE, int(strlen(END_RESPONSE)));
	  //cout << END_RESPONSE << endl;
	}
	else{
	  jString += string(get_char);
	  ssl_write(ssl, OK_RESPONSE, int(strlen(OK_RESPONSE)));
	  //cout << OK_RESPONSE << endl;
	}

	break;

      case SSL_ERROR_ZERO_RETURN:
	err_exit("closed...");

      default:
	berr_exit("SSL read problem...");
      }
  }

  cout << "get json message..." << endl;
  return jString;
}

int checkResponse(SSL *ssl){
  int r;
  char get_char[10];

  while(1){
    initialized_char(get_char, 10);

    r = SSL_read(ssl, get_char, 10);
    //cout << get_char << endl;
    switch(SSL_get_error(ssl, r))
      {
      case SSL_ERROR_NONE:
	//cout << string(get_char) << endl;
	if(string(get_char) == "OK")
	  return 1;
	else if(string(get_char) == "END"){
	  cout << "SUCCEED sending result message..." << endl;
	  return 0;
	}
	else
	  err_exit("fail to send result message...");

      default:
	break;
	//berr_exit("SSL read problem...");
      }
  }

  return 0;
}

void send_result(SSL *ssl, int sock, string ct_result){
  cout << "START sending result message..." << endl;

  int length = (int)ct_result.size();
  int start = 0;
  ifstream ifs;
  char post_char[BUFSIZE];

  do{
    if(length > (BUFSIZE-5)){ // (BUFSIZE-5)bitずつJSON(string)を送信する。
      initialized_char(post_char, BUFSIZE);

      for(int i=start; i<start+(BUFSIZE-5); i++)
	post_char[i-start] = ct_result[i];
      //cout << post_char << endl;

      ssl_write(ssl, post_char, int(strlen(post_char)));

      start += (BUFSIZE-5);
      length -= (BUFSIZE-5);
    }
    else if(length == 0 && start == (int)ct_result.size()){ // ファイル終了マークの送信
      ssl_write(ssl, ENDMARK, int(strlen(ENDMARK)));
      //cout << ENDMARK << endl;
    }
    else{// (BUFSIZE-5)bit未満の残りJSON(string)を送信する。
      initialized_char(post_char, BUFSIZE);

      for(int i=0; i<length; i++)
	post_char[i] = ct_result[start+i];
      //cout << post_char << endl;

      ssl_write(ssl, post_char, int(strlen(post_char)));

      start += length;
      length -= length;
    }
  }while(checkResponse(ssl) == 1);
}

void cerr_exit(string err){
  cout << err << endl;
  exit(1);
}















// OpenABE decrypt.cppより引用、編集
// ref: https://github.com/zeutro/openabe/blob/master/cli/decrypt.cpp
string runABEDecrypt(OpenABE_SCHEME scheme_type, string mpkFile,
		     string& suffix, string& secretkey, string& ciphertextFile){
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEContextSchemeCCA> schemeContext = nullptr;
  std::unique_ptr<OpenABECiphertext> ciphertext1 = nullptr, ciphertext2 = nullptr;

  string mpkID = MPK_ID, skID = secretkey;
  
  // read the file
  OpenABEByteString mpkBlob, skBlob, ct1Blob, ct2Blob;
  string plaintext;

#ifdef TIME_MEASURING
  auto start = chrono::system_clock::now();
#endif
  
  try{
    // Initialize a OpenABEContext structure
    schemeContext = OpenABE_createContextABESchemeCCA(scheme_type);
    if(schemeContext == nullptr)
      cerr_exit("unable to create a new context.");

    // load KP/CP public params
    mpkBlob = ReadFile(mpkFile.c_str());
    if(mpkBlob.size() == 0)
      cerr_exit("master public parameters not encoded properly.");
    
    if((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR)
      cerr_exit("unable to load the master public parameters.");
    
    skBlob = Base64Decode(secretkey);
    //cout << skBlob << endl;

    ct1Blob = ReadBlockFromFile(CT1_BEGIN_HEADER, CT1_END_HEADER, ciphertextFile.c_str());
    if(ct1Blob.size() == 0)
      cerr_exit("ABE ciphertext not encoded properly.");
    
    // Load the ciphertext components
    ciphertext1.reset(new OpenABECiphertext);
    ciphertext1->loadFromBytes(ct1Blob);

    ct2Blob = ReadBlockFromFile(CT2_BEGIN_HEADER, CT2_END_HEADER, ciphertextFile.c_str());
    if(ct2Blob.size() == 0)
      cerr << "AEAD ciphertext not encoded properly." << endl;
  }
  catch (OpenABE_ERROR& error){
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    exit(1);
  }

  try{
    // now we can load the user's secret key
    if((result = schemeContext->loadUserSecretParams(skID, skBlob)) != OpenABE_NOERROR){
      cerr << "Unable to load user's decryption key" << endl;
      throw result;
    }
    
    ciphertext2.reset(new OpenABECiphertext);
    ciphertext2->loadFromBytesWithoutHeader(ct2Blob);

    // now we can decrypt
    if((result = schemeContext->decrypt(mpkID, skID, plaintext, ciphertext1.get(), ciphertext2.get())) != OpenABE_NOERROR)
      throw result;
  }
  catch (OpenABE_ERROR & error){
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    exit(1);
  }

#ifdef TIME_MEASURING
  auto end = chrono::system_clock::now();
  auto diff = end - start;

  cout << "decrypt file time: "
       << chrono::duration_cast<chrono::microseconds>(diff).count() << "[microsec]\n" << endl;

  ofstream ofs(timeFile.c_str(), ios::app);
  ofs << chrono::duration_cast<chrono::microseconds>(diff).count();
  ofs << ", ";
  ofs.close();
#endif
  
  //return plaintext;
  return Base64Encode((unsigned const char *)plaintext.c_str(), plaintext.size());
}

// OpenABE encrypt.cppより引用、編集
// ref: https://github.com/zeutro/openabe/blob/master/cli/encrypt.cpp
string runABEEncrypt(OpenABE_SCHEME scheme_type, string mpkFile,
		     string& suffix, string& func_input, string& plaintext){
  // 念のため。もしここでcerr_exitになったらどうするのだろうか...
  try{
    size_t inputLen = plaintext.size();
    if(inputLen == 0 || inputLen > MAX_FILE_SIZE)
      cerr_exit("re-encrypt data is either empty or too big! Can encrypt up to 4GB files.");
  }
  catch(const std::ios_base::failure& e){
    cerr << e.what() << endl;
    exit(1);
  }

  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEContextSchemeCCA> schemeContext = nullptr;
  std::unique_ptr<OpenABEFunctionInput> funcInput = nullptr;
  string mpkID = MPK_ID;
  
  OpenABEByteString ct1Blob, ct2Blob, mpkBlob;
  string inputStr = Base64Decode(plaintext);
  string ctBlobStr = "";

#ifdef TIME_MEASURING
  auto start = chrono::system_clock::now();
#endif
  
  try{
    // Initialize a OpenABEContext structure
    schemeContext = OpenABE_createContextABESchemeCCA(scheme_type);
    if(schemeContext == nullptr)
      cerr_exit("unable to create a new context");
    
    // next, get the functional input for encryption (based on scheme type)
    if(scheme_type == OpenABE_SCHEME_KP_GPSW)
      funcInput = createAttributeList(func_input);
    else if(scheme_type == OpenABE_SCHEME_CP_WATERS)
      funcInput = createPolicyTree(func_input);

    //cout << funcInput.get() << endl;
    
    ASSERT(funcInput != nullptr, OpenABE_ERROR_INVALID_INPUT);

    // for KP and CP, we only have to do this once
    mpkBlob = ReadFile(mpkFile.c_str());
    if(mpkBlob.size() == 0)
      cerr_exit("master public parameters not encoded properly.");
    
    if((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR)
      cerr_exit("unable to load the master public parameters");
    
    std::unique_ptr<OpenABECiphertext> ciphertext1(new OpenABECiphertext);
    std::unique_ptr<OpenABECiphertext> ciphertext2(new OpenABECiphertext);
    if((result = schemeContext->encrypt(mpkID, funcInput.get(), inputStr, ciphertext1.get(), ciphertext2.get())) != OpenABE_NOERROR){
      cerr << "error occurred during encryption" << endl;
      throw result;
    }

    // write to disk
    ciphertext1->exportToBytes(ct1Blob);
    ciphertext2->exportToBytesWithoutHeader(ct2Blob);
    ctBlobStr += CT1_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct1Blob.getInternalPtr(), ct1Blob.size()) + NL;
    ctBlobStr += CT1_END_HEADER;
    ctBlobStr += NL;
    ctBlobStr += CT2_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct2Blob.getInternalPtr(), ct2Blob.size()) + NL;
    ctBlobStr += CT2_END_HEADER;
    ctBlobStr += NL;
  }
  catch(OpenABE_ERROR & error){
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
  }

#ifdef TIME_MEASURING
  auto end = chrono::system_clock::now();
  auto diff = end - start;

  cout << "Encypt time: "
       << chrono::duration_cast<chrono::microseconds>(diff).count() << "[microsec]" << endl;
  
  ofstream ofs(timeFile.c_str(), ios::app);
  ofs << chrono::duration_cast<chrono::microseconds>(diff).count();
  ofs << "\n";
  ofs.close();
#endif
  
  return ctBlobStr;
}

void getDataFromPlainText(string data, vector<double>& y, vector< vector<double> >& x, int& index, int& column){
  stringstream ss{Base64Decode(data)};
  string strint;
  vector<string> dataline;
  int count = 0;

  while(getline(ss, strint, '\n')) {
    //cout << strint << endl;
    
    if(count == 0){
      index = stoi(strint);
      //cout << index << endl;
    }
    else if(count == 1){
      column = stoi(strint);
      //cout << column << endl;

      y.resize(index);
      x.resize(index);
      dataline.resize(column);

      for(int i=0; i<index; i++){
	x[i].resize(column);
      }
    }
    else{
      dataline = split(strint, ' ');

      for(int i=0; i<column; i++){
	if(i==0){
	  y[count-2] = stoi(dataline[i]);
	  x[count-2][i] = 1.0;
	  //cout << "y[" << count-2 << "]: " << y[count-2] << "\nx[" << i << "]: ";
	}
	else{
	  x[count-2][i] = stod(dataline[i]);
	}

	//cout << x[count-2][i] << ", ";
      }
      //cout << endl;
    }
    
    count++;
  }
}

double getSigmoid(vector<double> x, vector<double> theta, int column){
  double param = 0.0;

  for(int i=0; i<column; i++)
    param -= theta[i] * x[i];

  return 1 / (1 + exp(param));
}

string LogisticRegression(string data){
  vector< vector<double> > x;
  vector<double> theta, y, diff;
  int trainIndex, trainColumn;
  double LLF, sum, sigmoid;
  string thetaText;
  
  // constant number.
  int lambda = 1;
  int iteration = 100;
  double rate = 0.01;
  
  // get dataset. 実装要検討!
  getDataFromPlainText(data, y, x, trainIndex, trainColumn);
  cout << "train data(index): " << trainIndex << ", train data(column, include class): " << trainColumn << endl;

  // initialize vector.
  diff.resize(trainIndex);
  theta.resize(trainColumn);

  // initialize theta.
  random_device random;
  mt19937 mt(random());
  uniform_real_distribution<> rand(-0.1, 0.1);

  for(int i=0; i<trainColumn; i++){
    theta[i] = rand(mt);
    //theta[i] = 0.0;
  }

  // update theta.
  cout << "start calculation theta..." << endl;

#ifdef TIME_MEASURING
  auto start = chrono::system_clock::now();
#endif

  for(int itr=0; itr<iteration; itr++){
    // for each theta.
    for(int j=0; j<trainColumn; j++){
      sum = 0.0;

      for(int i=0; i<trainIndex; i++){
	if(j==0){
	  sigmoid = getSigmoid(x[i], theta, trainColumn);
	  diff[i] = sigmoid - y[i];
	}
	
	sum += diff[i] * x[i][j];
      }
      
      // calculate differentiated Log-likelihood function(LLF, include Regularization item).
      LLF = (lambda * theta[j] + sum) / trainIndex;

      // gradient descent method.
      theta[j] = theta[j] - rate * LLF;
    }
  }

#ifdef TIME_MEASURING
  auto end = chrono::system_clock::now();
  auto time = end - start;

  cout << "calculation LR time: "
       << chrono::duration_cast<chrono::microseconds>(time).count() << "[microsec]" << endl;
  
  ofstream ofs(timeFile.c_str(), ios::app);
  ofs << chrono::duration_cast<chrono::microseconds>(time).count();
  ofs << ", ";
  ofs.close();
#endif
  
  cout << "end calculation theta...\n" << endl;
  
  for(int i=0; i<trainColumn; i++){
    thetaText += to_string(theta[i]) + "\n";
    //cout << theta[i] << endl;
  }
  //cout << thetaText;

  return Base64Encode((unsigned const char *)thetaText.c_str(), thetaText.size());
}

// replacedStr内の単語"from"を"to"に変換する関数
string replaceString(string& replacedStr, string from, string to) {
  const unsigned int pos = replacedStr.find(from);
  const int len = from.length();
  
  if (pos == string::npos || from.empty()) {
    return replacedStr;
  }

  return replacedStr.replace(pos, len, to);
}

// ref: https://qiita.com/sh-o/items/50d7c3d53bd1cd9cadc0
void searchFile(OpenABE_SCHEME scheme_type, string mpkFile, string& suffix, string& secretkey, string path, vector<string>& fileNames){
  int i, dirElements;
  string search_path;

  struct stat stat_buf;
  struct dirent **namelist=NULL;

  // dirElements にはディレクトリ内の要素数が入る
  dirElements = scandir(path.c_str(), &namelist, NULL, NULL);

  if(dirElements == -1){
    cout << "ERROR" <<  endl;
  }
  else{
    //ディレクトリかファイルかを順番に識別
    for(i=0; i<dirElements; i++){
      if((strcmp(namelist[i] -> d_name, ".\0") != 0) && (strcmp(namelist[i] -> d_name, "..\0") != 0)){ // "." と ".." を除く
	search_path = path + string(namelist[i] -> d_name); //search_pathには検索対象のフルパスを格納する

	if(stat(search_path.c_str(), &stat_buf) == 0){ // ファイル情報の取得の成功
	  if((stat_buf.st_mode & S_IFMT) != S_IFDIR) // ディレクトリでない場合(ファイルの場合)
	    fileNames.push_back(search_path);
	}
	else // ファイル情報の取得の失敗
	  cout << "ERROR" <<  endl << endl;
      }
    }
  }
  
  free(namelist);
  return;
}



int main(int argc, char **argv){
  // prepare for SSL
  int sock, s;
  BIO *sbio;
  SSL_CTX *ctx;
  SSL *ssl;
  int r;

  // prepare for ABE decrypt scheme.
  string suffix, plaintext, ciphertext_file;
  string scheme_name = "CP";
  string mpk_file = "mpk.cpabe";

  // prepare for analytics.
  string theta;
  string err;
  string secretkey, jString;
  
  // prepare for ABE re-encrypt scheme.
  string func_input = "", ct_result = "";

  // setup ABE scheme.(detail on each file.)
  OpenABE_SCHEME scheme = checkForScheme(scheme_name, suffix);

  InitializeOpenABE();
  
  // create SSL context.
  ctx = initialize_ctx(KEYFILE, PASSWORD);
  //load_dh_params(ctx, DHFILE); // 必要性が理解できなかった.要確認
  //generate_eph_rsa_key(ctx);

  SSL_CTX_set_session_id_context(ctx, (const unsigned char *)&s_server_session_id_context,
				 sizeof s_server_session_id_context);
  sock = tcp_listen(PORT);

  
  while(1){
    cout << "*** GET READY for SSL and ABE ***" << endl;
     
    if((s = accept(sock, 0, 0)) < 0)
      err_exit("Problem accepting...");
  
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, sbio, sbio);
    
    if((r = SSL_accept(ssl)) <= 0)
      berr_exit("SSL accept error...");

    // get json -> user's secret key.
    jString = getJSON(ssl, s);

    const auto json = json11::Json::parse(jString, err);
    secretkey = json["SK"].string_value();
    ciphertext_file = "./data/" + json["anlFile"].string_value();
    cout << "check: " << ciphertext_file << endl;
    
    // 復号条件はカンマ区切りでないので、変換する。
    func_input = json["policy"].string_value();
    replaceString(func_input, ",", " and ");
    //cout << func_input << endl;
    
    plaintext = runABEDecrypt(scheme, mpk_file, suffix, secretkey, ciphertext_file);
    //cout << Base64Decode(plaintext) << endl; 

    theta = LogisticRegression(plaintext);
    
    //cout << "re-encryption functional input: "<< func_input << endl;
    ct_result = runABEEncrypt(scheme, mpk_file, suffix, func_input, theta);

    // return result to cliet.
    send_result(ssl, s, ct_result);
  }
  
  // close OpenABE, SSL.
  ShutdownOpenABE();
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(s);
  destroy_ctx(ctx);
  
  return 0;
}
