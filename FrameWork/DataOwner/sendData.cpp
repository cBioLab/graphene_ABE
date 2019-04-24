#include "SSLclient.hpp"
#include "common.h"
#include "json11.hpp"

using namespace oabe;

const int PORT = 12345;
const int BUFSIZE = 16384;
char ENDMARK[] = "*** END OF MESSAGE ***";


void cerr_exit(string err){
  cout << err << endl;
  exit(1);
}

// OpenABE encrypt.cppより引用、編集
// ref: https://github.com/zeutro/openabe/blob/master/cli/encrypt.cpp
void runABEEncrypt(OpenABE_SCHEME scheme_type, string mpkFile, string& suffix,
		     string& func_input, string& input_file, string& ABE_CT_BLOCK, string& CT_BLOCK){
  cout << "START ABE Encryption..." << endl;

  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEContextSchemeCCA> schemeContext = nullptr;
  std::unique_ptr<OpenABEFunctionInput> funcInput = nullptr;
  string mpkID = MPK_ID;

  OpenABEByteString ct1Blob, ct2Blob, mpkBlob;
  string inputStr, ctBlobStr = "";

  std::unique_ptr<OpenABECiphertext> ciphertext1(new OpenABECiphertext);
  std::unique_ptr<OpenABECiphertext> ciphertext2(new OpenABECiphertext);
    
  try{
    getFile(inputStr, input_file);
    size_t inputLen = inputStr.size();
    if(inputLen == 0 || inputLen > MAX_FILE_SIZE)
      cerr_exit("re-encrypt data is either empty or too big! Can encrypt up to 4GB files.");
  }
  catch(const std::ios_base::failure& e){
    cerr << e.what() << endl;
    exit(1);
  }

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

    if((result = schemeContext->encrypt(mpkID, funcInput.get(), inputStr, ciphertext1.get(), ciphertext2.get())) != OpenABE_NOERROR){
      cerr << "error occurred during encryption" << endl;
      throw result;
    }

    ciphertext1->exportToBytes(ct1Blob);
    ciphertext2->exportToBytesWithoutHeader(ct2Blob);

    /*
    // write to disk
    ctBlobStr += CT1_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct1Blob.getInternalPtr(), ct1Blob.size()) + NL;
    ctBlobStr += CT1_END_HEADER;
    ctBlobStr += NL;
    ctBlobStr += CT2_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct2Blob.getInternalPtr(), ct2Blob.size()) + NL;
    ctBlobStr += CT2_END_HEADER;
    ctBlobStr += NL;
    */

    ABE_CT_BLOCK = Base64Encode(ct1Blob.getInternalPtr(), ct1Blob.size());
    CT_BLOCK = Base64Encode(ct2Blob.getInternalPtr(), ct2Blob.size());
  }
  catch(OpenABE_ERROR & error){
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
  }

  //return ctBlobStr;
}

string getJsonString(string filename, string ABE_CT_BLOCK, string CT_BLOCK){
  string attr1 = R"({"filename":)";
  string attr2 = R"(, "ABE_CT_BLOCK":)";
  string attr3 = R"(, "CT_BLOCK":)";

  string JsonString = attr1 + '"' + filename + '"' + attr2 + '"' + ABE_CT_BLOCK + '"' + attr3 + '"' + CT_BLOCK + '"' + "}";
  return JsonString;
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
	else if(string(get_char) == "END")
	  return 0;

      default:
	break;
	//berr_exit("SSL read problem...");
      }
  }

  return 0;
}

void sendJSON(SSL *ssl, int sock, string JSONString, int BUFSIZE){
  cout << "START send json message..." << endl;

  int ofcmode;  
  int length = (int)JSONString.size();
  int start = 0;
  ifstream ifs;
  char post_char[BUFSIZE];
  
  // まず、ソケットを非ブロックにする。
  ofcmode = fcntl(sock, F_GETFL, 0);
  ofcmode |= O_NDELAY;
  if(fcntl(sock, F_SETFL, ofcmode))
    err_exit("Could not make socket nonblocking...");

  do{
    if(length > (BUFSIZE-5)){ // (BUFSIZE-5)bitずつJSON(string)を送信する。
      initialized_char(post_char, BUFSIZE);
    
      for(int i=start; i<start+(BUFSIZE-5); i++)
	post_char[i-start] = JSONString[i];
      //cout << post_char << endl;
      
      ssl_write(ssl, post_char, int(strlen(post_char)));
      
      start += (BUFSIZE-5);
      length -= (BUFSIZE-5);
    }
    else if(length == 0 && start == (int)JSONString.size()){ // ファイル終了マークの送信
      ssl_write(ssl, ENDMARK, int(strlen(ENDMARK)));
      //cout << ENDMARK << endl;
    }
    else{// (BUFSIZE-5)bit未満の残りJSON(string)を送信する。
      initialized_char(post_char, BUFSIZE);

      for(int i=0; i<length; i++)
	post_char[i] = JSONString[start+i];
      //cout << post_char << endl;

      ssl_write(ssl, post_char, int(strlen(post_char)));      

      start += length;
      length -= length;
    }
  }while(checkResponse(ssl) == 1);

  cout << "END send json message..." << endl;
  return;
}


int main(int argc, char **argv){  
  // prepare for SSL
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  int sock;

  // prepare for ABE encrypt scheme.
  string suffix, ABE_CT_BLOCK, CT_BLOCK;
  string scheme_name = "CP";
  string mpk_file = "mpk.cpabe";
  string input_file = "./BCW/train-BCW.data"; //(仮)
  string policy = "iwata and daiki"; //(仮)
  string filename = "train-BCW.data.cpabe"; //(仮)

  // for json.
  string jString, err;

  if (argc != 4){
    cout << "Input not correct..." << endl;
    cout << "./sendData [input file] [filename on server] [policy]";
    exit(-1);
  }
  input_file = argv[1];
  filename = argv[2];
  policy = argv[3];
  

  // setup ABE scheme.(detail on each file.)
  OpenABE_SCHEME scheme = checkForScheme(scheme_name, suffix);

  InitializeOpenABE();

  
  // file encryption.
  runABEEncrypt(scheme, mpk_file, suffix, policy, input_file, ABE_CT_BLOCK, CT_BLOCK);
  //cout << ABE_CT_BLOCK << endl;
  //cout << CT_BLOCK << endl;
  
  jString = getJsonString(filename, ABE_CT_BLOCK, CT_BLOCK);
  //cout << jString << endl;
  //const auto json = json11::Json::parse(jString, err);
  //cout << "jString[filename]: " << json["filename"].string_value() << endl;
  //cout << "jString[ABE_CT_BLOCK]: " << json["ABE_CT_BLOCK"].string_value() << endl;
  //cout << "jString[CT_BLOCK]: " << json["CT_BLOCK"].string_value() << endl;

  // create SSL context.
  ctx = initialize_ctx(KEYFILE, PASSWORD);

  sock = tcp_connect(PORT);

  // SSLソケットに接続する。
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);
  
  if(SSL_connect(ssl) <= 0)
    berr_exit("SSL connect error...");

  check_cert_chain(ssl, HOST);

  // 読み込みと書き込み。
  sendJSON(ssl, sock, jString, BUFSIZE);

  // close OpenABE, SSL.
  ShutdownOpenABE();
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sock);
  destroy_ctx(ctx);
  
  return 0;
}
