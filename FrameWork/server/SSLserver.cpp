#include "SSLserver.hpp"

BIO *bio_err = 0;
const static char *pass;
static int password_cb(char * buf, int num, int rwflag, void *userdata);
static void sigpipe_handle(int x);

// 単純なエラーと終了ルーチン。
int err_exit(const char *string){
  fprintf(stderr, "%s\n", string);
  exit(0);
}

// SSLエラーを表示して終了する。
int berr_exit(const char *string){
  BIO_printf(bio_err, "%s\n", string);
  ERR_print_errors(bio_err);
  exit(0);
}

// Passはスレッドセーフでない。
static int password_cb(char *buf, int num, int rwflag, void *userdata){
  if(num < int(strlen(pass)+1))  return(0);
  
  strcpy(buf, pass);
  return(strlen(pass));
}

static void sigpipe_handle(int x){
}

// ref: https://kotaeta.com/54483596
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx){
  return preverify_ok;
}


SSL_CTX *initialize_ctx(const char *keyfile, const char *password){
  SSL_CTX *ctx;
  
  if(!bio_err){
    // グローバルなシステムの初期化
    SSL_library_init();
    SSL_load_error_strings();
    
    // エラーの書き込みコンテクスト
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  }
  
  // SIGPIPEハンドラをセットアップ
  signal(SIGPIPE, sigpipe_handle);
  
  // コンテキストを作成。
  // ref: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_new.html
  //ctx = SSL_CTX_new(SSLv23_server_method());
  ctx = SSL_CTX_new(TLS_server_method());
  
  // 証明書をロードする
  if(!(SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM))){
    berr_exit("Could not read certificate file... ");
  }

  // 秘密鍵をロードする
  pass = password;
  SSL_CTX_set_default_passwd_cb(ctx, password_cb);
  if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
    berr_exit("Could not read key file... ");

  // 信頼するCAをロードする
  if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST, 0)))
    berr_exit("Could not read CA list...");

  // 証明書検証機能の有効化
  // ref: https://blogs.yahoo.co.jp/udumge/19232934.html
  SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
  
  SSL_CTX_set_verify_depth(ctx, 9);
      
  return ctx;
}

int tcp_listen(int PORT){
  int sock;
  struct sockaddr_in sin;
  int val = 1;

  if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    err_exit("Could not make socket...");

  memset(&sin, 0, sizeof(sin));
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(PORT);
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

  if(bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    berr_exit("Could not bind...");

  listen(sock, 5);

  return(sock);
}


void load_dh_params(SSL_CTX *ctx, const char *file){
  DH *ret = 0;
  BIO *bio;

  if((bio = BIO_new_file(file, "r")) == NULL)
    berr_exit("Could not open DH file...");

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if(SSL_CTX_set_tmp_dh(ctx, ret) < 0)
    berr_exit("Could not set DH parameters...");
}

void generate_eph_rsa_key(SSL_CTX *ctx){
  /* RSA_generate_key() is deprecated...

    RSA *rsa;

    rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);

    if(!SSL_CTX_set_tmp_rsa(ctx, rsa))
      berr_exit("Could not set RSA key...");

    RSA_free(rsa);
  */

  RSA *rsa = RSA_new();
  BIGNUM *e = BN_new();
  BN_set_word(e, RSA_F4);

  if(RSA_generate_key_ex(rsa, 512, e, NULL) == 0)
    berr_exit("Could not set RSA key...");

  RSA_free(rsa);
  BN_free(e);
}


void echo(SSL *ssl, int s, int BUFSIZE){
  char buf[BUFSIZE];
  int r, len, offset;

  while(1){
    // データを読み取る。
    r = SSL_read(ssl, buf, BUFSIZE);

    switch(SSL_get_error(ssl, r)){
    case SSL_ERROR_NONE:
      fwrite(buf, 1, r, stdout); //出力
      //cout << buf << endl;
      len = r;
      break;

    case SSL_ERROR_ZERO_RETURN:
      goto end;

    default:
      berr_exit("SSL read problem...");
    }

    // 全てを書き終えるまで書き込みを続ける。
    offset = 0;

    while(len){
      r = SSL_write(ssl, buf + offset, len);

      switch(SSL_get_error(ssl, r)){
      case SSL_ERROR_NONE:
	len -= r;
	offset += r;
	break;

      default:
	berr_exit("SSL write problem...");
      }
    }
  }

 end:
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(s);
}


void destroy_ctx(SSL_CTX *ctx){
  SSL_CTX_free(ctx);
}

void initialized_char(char *character, int size){
  for(int i=0; i<size; i++)
    character[i] = '\0';
}

