#include "SSLclient.hpp"
#include "json11.hpp"

const int PORT = 54345;
const int BUFSIZE = 16384;
char ENDMARK[] = "*** END OF MESSAGE ***";
char OK_RESPONSE[] = "OK";
char END_RESPONSE[] = "END";
const string START = "-----BEGIN USER PRIVATE KEY BLOCK-----";
const string END = "-----END USER PRIVATE KEY BLOCK-----";

#define USAGE \
    "usage: [ -s SK file ] [ -p policy ] [ -a analyze filename ] [ -r result filename ]\n" \
    "\t-s : your ABE secret key file.\n"\
    "\t-p : policy that you use. ** input policy within your authority!! **\n"\
    "\t-a : input analyze file name.\n"\
    "\t-r : input return file name.\n\n"\

void string_to_charArray(char *charArray, int size, string message){
  initialized_char(charArray, size);

  for(int i=0; i<int(message.size()); i++)
    charArray[i] = message[i];

  return;
}

string getSKtext(string filename){
  string SKtext, line;
  ifstream ifs;
  
  // check whether we open file or not.
  ifs.open(filename);
  if(ifs.fail())
    err_exit("Could not read secret key FILE...");

  while(getline(ifs, line)){
    if(line != START && line != END)
      SKtext += line;
  }
  ifs.close();

  //cout << SKtext << endl;
  return SKtext;
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
	  cout << "SUCCESS sending json message..." << endl;
	  return 0;
	}
	else{
	  err_exit("fail to send json message...");
	}
      default:
	break;
	//berr_exit("SSL read problem...");
      }
  }

  return 0;
}

void sendJSON(SSL *ssl, int sock, string JSONString){
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
}

string get_result(SSL *ssl, int s){
  char get_char[BUFSIZE];
  int r, flag = 0;
  string ciphertext = "";

  cout << "Waiting for returning result..." << endl;

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
	  ciphertext += string(get_char);
	  ssl_write(ssl, OK_RESPONSE, int(strlen(OK_RESPONSE)));
	  //cout << OK_RESPONSE << endl;
	}

	break;

      case SSL_ERROR_ZERO_RETURN:
	err_exit("closed...");

      default:
	break;
	//berr_exit("SSL read problem...");
      }
  }
  
  return ciphertext;
}

void savefile(string result, string getFile){
  ofstream ofs(getFile.c_str(), ios::out);
  ofs << result;
  ofs.close();
}


string getJsonString(string SK, string policy, string anlFile){
  string tmp1 = R"({"SK":)";
  string tmp2 = R"(, "policy":)";
  string tmp3 = R"(, "anlFile":)";

  string JsonString = tmp1 + '"' + SK + '"' + tmp2 + '"' + policy + '"' + tmp3 + '"' + anlFile + '"' + "}";
  return JsonString;
}

int main(int argc, char **argv){  
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  int sock, opt;
  string prvFile, policy, getFile, analyzeFile;
  string jString, secretkey, result;
  
  if(argc != 9){
    fprintf(stderr, USAGE);
    exit(-1);
  }
  
  while((opt = getopt(argc, argv, "s:p:r:a:")) != EOF){
    switch(opt)
      {
      case 'p': policy = string(optarg); break;
      case 's': prvFile = string(optarg); break;
      case 'r': getFile = string(optarg); break;
      case 'a': analyzeFile = string(optarg); break;
      case '?': fprintf(stderr, USAGE);
      default: cout << endl; exit(-1);
      }
  }
  cout << "***** SEND DATA *****" << endl;
  cout << "     SK file: " << prvFile << endl;
  cout << "analyze file: " << analyzeFile << endl;
  cout << "      policy: " << policy << endl;
  cout << " result file: " << getFile << endl;
  cout << "***** SEND DATA *****\n" << endl;
  secretkey = getSKtext(prvFile);
  
  jString = getJsonString(secretkey, policy, analyzeFile);
  //cout << jString << endl;
  
  // create SSL context.
  ctx = initialize_ctx(KEYFILE, PASSWORD);

  // TCPソケットに接続する。
  sock = tcp_connect(PORT);

  // SSLソケットに接続する。
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);

  if(SSL_connect(ssl) <= 0)
    berr_exit("SSL connect error...");

  check_cert_chain(ssl, HOST);

  sendJSON(ssl, sock, jString);
  
  // SKを送信したらresult dataが返ってくるとする。
  result = get_result(ssl, sock);

  savefile(result, getFile);
  
  // 終了処理
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sock);
  destroy_ctx(ctx);
  
  return 0;
}
