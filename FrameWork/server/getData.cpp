#include "SSLserver.hpp"
#include "common.h"
#include "json11.hpp"

const int PORT = 12345;
const int BUFSIZE = 16384;
static int s_server_session_id_context = 1;
const string ENDMARK = "*** END OF MESSAGE ***";
char OK_RESPONSE[] = "OK";
char END_RESPONSE[] = "END";

void ssl_write(SSL *ssl, char *character, int size){
  int r = SSL_write(ssl, character, size);

  if(SSL_get_error(ssl, r) != 0)
    berr_exit("SSL write problem...");
}

string getJSON(SSL *ssl, int s, int size){
  char get_char[size];
  int r, flag = 0;
  string line, jString = "";

  cout << "START get json message..." << endl;
  
  while(flag == 0){
    initialized_char(get_char, size);
    line = "";
    
    // データを読み取る。
    r = SSL_read(ssl, get_char, size);
    
    switch(SSL_get_error(ssl, r))
      {
      case SSL_ERROR_NONE:
	line = string(get_char);
	//cout << line << endl;

	if(line == ENDMARK){
	  flag = 1;
	  ssl_write(ssl, END_RESPONSE, int(strlen(END_RESPONSE)));
	  //cout << END_RESPONSE << endl;
	}
	else{
	  jString += line;
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

  cout << "End get json message..." << endl;
  return jString;
}

bool checkFileExist(string filename){
  ifstream ifs(filename);
  return ifs.is_open();
}


void storeCipherText(string jString, string storePATH){
  string err, filename;
  
  auto json = json11::Json::parse(jString, err);
  //cout << "jString[filename]: " << json["filename"].string_value() << endl;
  //cout << "jString[ABE_CT_BLOCK]: " << json["ABE_CT_BLOCK"].string_value() << endl;
  //cout << "jString[CT_BLOCK]: " << json["CT_BLOCK"].string_value() << endl;

  filename = storePATH + json["filename"].string_value();
  if(!checkFileExist(filename)){
    // store CipherText file.
    ofstream ofs(filename.c_str(), ios::out);
    ofs << CT1_BEGIN_HEADER;
    ofs << NL + json["ABE_CT_BLOCK"].string_value() + NL;
    ofs << CT1_END_HEADER;
    ofs << NL;
    ofs << CT2_BEGIN_HEADER;
    ofs << NL + json["CT_BLOCK"].string_value() + NL;
    ofs << CT2_END_HEADER;
    ofs << NL;
    ofs.close();
  }
  else
    err_exit("ERROR: same name file already existed. If you store this file, you need to change the filename...");
}


int main(int argc, char **argv){
  // for SSL protocol.
  int sock, s;
  BIO *sbio;
  SSL_CTX *ctx;
  SSL *ssl;
  int r;

  // for store data.
  string jString;
  string storePATH = "./data/";
  
  // SSLコンテキストを作成
  ctx = initialize_ctx(KEYFILE, PASSWORD);
  //load_dh_params(ctx, DHFILE); // 必要性が理解できなかった.要確認
  //generate_eph_rsa_key(ctx);

  SSL_CTX_set_session_id_context(ctx, (const unsigned char *)&s_server_session_id_context,
				 sizeof s_server_session_id_context);
  sock = tcp_listen(PORT);

  
  if((s = accept(sock, 0, 0)) < 0)
    err_exit("Problem accepting...");
  
  sbio = BIO_new_socket(s, BIO_NOCLOSE);
  ssl = SSL_new(ctx);
  SSL_set_bio(ssl, sbio, sbio);
  
  if((r = SSL_accept(ssl)) <= 0)
    berr_exit("SSL accept error...");

  // jsonファイルの受け取り
  jString = getJSON(ssl, s, BUFSIZE);

  // jsonの情報をファイルに書き込み
  storeCipherText(jString, storePATH);
  

  // close SSL.
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(s);
  destroy_ctx(ctx);
  return 0;
}
