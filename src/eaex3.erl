%%% File        : eaex3.erl
%%% Author      : Hans Svensson
%%% Description : Implementing AEX-3:
%%%               https://github.com/aeternity/AEXs/blob/master/AEXS/aex-3.md
%%% Created     : 6 Jan 2022 by Hans Svensson
-module(eaex3).

-define(ARGON2ID_OPSLIMIT, 3).
-define(ARGON2ID_MEMLIMIT, 65535).
-define(ARGON2ID_SALTSIZE, 16).

-define(PBKDF2_ROUNDS, 65535).
-define(PBKDF2_DKLEN, 32).
-define(PBKDF2_HASH, sha512).
-define(PBKDF2_SALTSIZE, 16).

-define(LIBSODIUM_SECRETBOX_NONCESIZE, 24).
-define(LIBSODIUM_SECRETBOX_KEYSIZE, 32).

-define(CHACHA20_NONCESIZE, 12).

-define(DEFAULT_ALGO, {pbkdf2, chacha20_poly1305}).

-export([create/4, create/5,
         create_masterkey/3, create_masterkey/4,
         create_mnemonic/3, create_mnemonic/4,
         decrypt/2,
         read/2,
         store/5, store/6,
         store_masterkey/4, store_masterkey/5,
         store_mnemonic/4, store_mnemonic/5]).

store_mnemonic(Mnemonic, Comment, Password, Path) ->
  store_mnemonic(Mnemonic, Comment, ?DEFAULT_ALGO, Password, Path).

store_mnemonic(Mnemonic, Comment, Algo, Password, Path) ->
  JSON = create_mnemonic(Mnemonic, Comment, Algo, Password),
  store_(JSON, Path).

store_masterkey(MasterKey, Comment, Password, Path) ->
  store_masterkey(MasterKey, Comment, ?DEFAULT_ALGO, Password, Path).

store_masterkey(MasterKey, Comment, Algo, Password, Path) ->
  JSON = create_masterkey(MasterKey, Comment, Algo, Password),
  store_(JSON, Path).

store(Type, Message, Comment, Password, Path) ->
  store(Type, Message, Comment, ?DEFAULT_ALGO, Password, Path).

store(Type, Message, Comment, Algo, Password, Path) ->
  JSON = create(Type, Message, Comment, Algo, Password),
  store_(JSON, Path).

store_(JSON, Path) ->
  Output = zj:encode(JSON),
  FileName =
    case filename:extension(Path) of
      ".json" -> Path;
      _ -> filename:join(Path, maps:get("id", JSON) ++ ".json")
    end,
  file:write_file(FileName, Output).

create_mnemonic(Mnemonic, Comment, Password) ->
  create_mnemonic(Mnemonic, Comment, ?DEFAULT_ALGO, Password).

create_mnemonic(Mnemonic, Comment, Algo, Password) ->
  create("ed25519-bip39-mnemonic", Mnemonic, "Mnemonic: " ++ Comment, Algo, Password).

create_masterkey(MasterKey, Comment, Password) ->
  create_masterkey(MasterKey, Comment, ?DEFAULT_ALGO, Password).

create_masterkey(MasterKey, Comment, Algo, Password) ->
  create("ed25519-slip0010-masterkey", MasterKey, "MasterKey: " ++ Comment, Algo, Password).

create(Type, Data, Comment, Password) ->
  create(Type, Data, Comment, ?DEFAULT_ALGO, Password).

create(Type, Data, Comment, {PwdHashAlgo, EncAlgo}, Password) ->
  KDFParams = pwd_hash_params(PwdHashAlgo),
  PwHash    = pwd_hash(KDFParams, Password),

  {CipherText, Params} = encrypt_algo(EncAlgo, Data, PwHash),
  CipherParams = {EncAlgo, CipherText, Params},

  UUID = uuid:uuid4(),

  JSON =
    #{"crypto"  => #{"secret_type" => Type},
      "id"      => uuid:to_string(UUID),
      "name"    => Comment,
      "version" => 1
     },
  add_cipher_params(CipherParams, add_kdf_params(KDFParams, JSON)).

read(File, Password) ->
  case file:read_file(File) of
    {ok, BinData} ->
      case zj:decode(BinData) of
        {ok, JSON} ->
          decrypt(JSON, Password);
        {error, _, Remains} ->
          io:format("Error, could not read file: ~s\n  "
                    "Reason: JSON parse failed at ~p\n", [File, Remains]);
        {incomplete, Parsed, _} ->
          io:format("Error, could not read file: ~s\n  "
                    "Reason: JSON file incomplete after ~p\n", [File, Parsed])
      end;
    {error, Reason} ->
      io:format("Error: Could not read file: ~s: Reason ~p\n", [File, Reason])
  end.

decrypt(JSON, Password) ->
  try
    assert_version(1, JSON),
    Crypto       = get_crypto(JSON),
    UUID         = get_id(JSON),
    Comment      = get_name(JSON),
    KDF          = get_kdf(Crypto),
    SecretType   = get_secret(Crypto),
    {CAlgo, CText, COpts} = get_cipher(Crypto),


    PwHash = pwd_hash(KDF, Password),

    case decrypt_algo(CAlgo, CText, PwHash, COpts) of
      {ok, SecretMsg} ->
        {ok, #{id      => UUID,
               message => SecretMsg,
               type    => SecretType,
               comment => Comment}};
      {error, R} ->
        io:format("Error, failed to decrypt: ~p\n", [R]),
        {error, {decrypt, R}}
    end
  catch throw:{ErrType, Reason} ->
    io:format("Decrypt: ~200p\n", [JSON]),
    io:format("Error, failed to decrypt, ~p: ~s\n", [ErrType, Reason]),
    {error, {ErrType, Reason}}
  end.

%% ---- Internal functions

%% ---- Key derivation and encrypt/decrypt

pwd_hash({argon2id, #{memlim := MemLimKb, opslim := OpsLim, salt := Salt}}, Password) ->
  enacl:pwhash(Password, Salt, OpsLim, MemLimKb * 1024);
pwd_hash({pbkdf2, #{rounds := Rounds, dklen := DKLen, hash := Hash, salt := Salt}}, Password) ->
  {ok, PwdHash} = epbkdf2:pbkdf2(Hash, Password, Salt, Rounds, DKLen),
  PwdHash.

encrypt_algo(xsalsa20_poly1305, Msg, Key) ->
  Nonce = crypto:strong_rand_bytes(?LIBSODIUM_SECRETBOX_NONCESIZE),
  {enacl:secretbox_easy(Msg, Nonce, Key), #{nonce => Nonce}};
encrypt_algo(chacha20_poly1305, Msg, Key) ->
  Nonce = crypto:strong_rand_bytes(?CHACHA20_NONCESIZE),
  {CMsg, MAC} = crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, Msg, <<>>, 16, true),
  {<<MAC/binary, CMsg/binary>>, #{nonce => Nonce}}.

decrypt_algo(xsalsa20_poly1305, CipherText, Key, #{nonce := Nonce}) ->
  enacl:secretbox_open_easy(CipherText, Nonce, Key);
decrypt_algo(chacha20_poly1305, CipherText, Key, #{nonce := Nonce}) ->
  <<MAC:16/binary, CMsg/binary>> = CipherText,
  case crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, CMsg, <<>>, MAC, false) of
    error -> {error, decrypt_failed};
    Msg   -> {ok, Msg}
  end.

%% ---- Default parameters for PwdHash

pwd_hash_params(argon2id) ->
  Salt = crypto:strong_rand_bytes(?ARGON2ID_SALTSIZE),
  argon2id_params(Salt);
pwd_hash_params(pbkdf2) ->
  Salt = crypto:strong_rand_bytes(?PBKDF2_SALTSIZE),
  pbkdf2_params(Salt).

argon2id_params(Salt) ->
  argon2id_params(?ARGON2ID_OPSLIMIT, ?ARGON2ID_MEMLIMIT, Salt).

argon2id_params(OpsLimit, MemLimitKiB, Salt) ->
  {argon2id, #{opslim => OpsLimit, memlim => MemLimitKiB, salt => Salt}}.

pbkdf2_params(Salt) ->
  pbkdf2_params(?PBKDF2_ROUNDS, ?PBKDF2_DKLEN, ?PBKDF2_HASH, Salt).

pbkdf2_params(Rounds, DKLen, Hash, Salt) ->
  {pbkdf2, #{rounds => Rounds, dklen => DKLen, hash => Hash, salt => Salt}}.

%% ---- Get/Set parameters from/to JSON
get_crypto(#{"crypto" := Crypto}) -> Crypto;
get_crypto(_) -> throw({missing_info, "crypto"}).

get_secret(#{"secret_type" := "ed25519-slip0010-masterkey"}) -> ed25519_slip0010_masterkey;
get_secret(#{"secret_type" := "ed25519-bip39-mnemonic"})     -> ed25519_bip39_mnemonic;
get_secret(#{"secret_type" := Unknown}) -> throw({bad_secret_type, Unknown});
get_secret(_)                           -> throw({missing_info, "crypto/secret_type"}).

get_id(#{"id" := UUID}) -> UUID;
get_id(_)               -> throw({missing_info, "id"}).

assert_version(ExpectedVsn, #{"version" := ExpectedVsn}) -> ok;
assert_version(ExpectedVsn, #{"version" := OtherVsn}) when is_integer(OtherVsn) ->
  throw({bad_version, "Got version " ++ integer_to_list(OtherVsn) ++
                      " expected " ++ integer_to_list(ExpectedVsn)});
assert_version(ExpectedVsn, #{"version" := _BadVsn}) ->
  throw({bad_version, "Version should be a number (expecting " ++ integer_to_list(ExpectedVsn) ++ ")"});
assert_version(_ExpectedVsn, _) ->
  throw({missing_info, "version"}).

get_name(#{"name" := Name}) -> Name;
get_name(_)                 -> "".

get_kdf(#{"kdf" := KDFAlgo, "kdf_params" := KDFParams}) ->
  case KDFAlgo of
    "argon2id" -> get_kdfparams(argon2id, KDFParams);
    "pbkdf2"   -> get_kdfparams(pbkdf2, KDFParams);
    _          -> throw({bad_kdf, KDFAlgo})
  end;
get_kdf(_) ->
  throw({missing_info, "crypto/kdf|kdf_params"}).

get_kdfparams(argon2id, #{"memlimit_kib" := MemLimKb, "opslimit" := OpsLim, "salt" := Salt}) ->
  {argon2id, #{memlim => MemLimKb, opslim => OpsLim,
               salt => check_hex_to_bin("crypto/kdf_params/salt", Salt)}};
get_kdfparams(argon2id, _) ->
  throw({bad_kdf_params, "Expected: memlimit_kib, opslimit and salt"});
get_kdfparams(pbkdf2, #{"c" := Rounds, "dklen" := DKLen, "prf" := Prf, "salt" := Salt}) ->
  {pbkdf2, #{rounds => Rounds, dklen => DKLen, hash => check_pbkdf2_prf(Prf),
             salt => check_hex_to_bin("crypto/kdf_params/salt", Salt)}};
get_kdfparams(pbkdf2, _) ->
  throw({bad_kdf_params, "Expected: c, dklen, prf and salt"}).

get_cipher(#{"symmetric_alg" := CipherAlg,
             "ciphertext" := HexCipher,
             "cipher_params" := CipherParams}) ->
  case CipherAlg of
    "chacha20-poly1305" ->
      case CipherParams of
        #{"nonce" := HexNonce} ->
          {chacha20_poly1305, check_hex_to_bin("crypto/ciphertext", HexCipher),
           #{nonce => check_hex_to_bin("crypto/cipher_params/nonce", HexNonce)}};
        _ ->
          throw({missing_info, "crypto/cipher_params/nonce"})
      end;
    "xsalsa20-poly1305" ->
      case CipherParams of
        #{"nonce" := HexNonce} ->
          {xsalsa20_poly1305, check_hex_to_bin("crypto/ciphertext", HexCipher),
           #{nonce => check_hex_to_bin("crypto/cipher_params/nonce", HexNonce)}};
        _ ->
          throw({missing_info, "crypto/cipher_params/nonce"})
      end;
    _ ->
      throw({bad_cipher_algo, CipherAlg})
  end;
get_cipher(_) ->
  throw({missing_info, "crypto/symmetric_alg|ciphertext|cipher_params"}).

add_kdf_params({argon2id, #{opslim := OpsLimit, memlim := MemLimitKiB, salt := Salt}},
               JSON = #{"crypto" := Crypto}) ->
  JSON#{
    "crypto" := Crypto#{
      "kdf" => "argon2id",
      "kdf_params" => #{"memlimit_kib" => MemLimitKiB,
                        "opslimit" => OpsLimit,
                        "salt" => bin_to_hex(Salt)}
     }
   };
add_kdf_params({pbkdf2, #{rounds := Rounds, dklen := DKLen, hash := Hash, salt := Salt}},
               JSON = #{"crypto" := Crypto}) ->
  JSON#{
    "crypto" := Crypto#{
      "kdf" => "pbkdf2",
      "kdf_params" => #{"c" => Rounds,
                        "dklen" => DKLen,
                        "prf" => lists:flatten(io_lib:format("hmac-~p", [Hash])),
                        "salt" => bin_to_hex(Salt)}
     }
   }.

add_cipher_params({xsalsa20_poly1305, CipherText, #{nonce := Nonce}},
                   JSON = #{"crypto" := Crypto}) ->
  JSON#{
    "crypto" := Crypto#{
      "symmetric_alg" => "xsalsa20-poly1305",
      "ciphertext" => bin_to_hex(CipherText),
      "cipher_params" => #{"nonce" => bin_to_hex(Nonce)}
     }
   };
add_cipher_params({chacha20_poly1305, CipherText, #{nonce := Nonce}},
                   JSON = #{"crypto" := Crypto}) ->
  JSON#{
    "crypto" := Crypto#{
      "symmetric_alg" => "chacha20-poly1305",
      "ciphertext" => bin_to_hex(CipherText),
      "cipher_params" => #{"nonce" => bin_to_hex(Nonce)}
     }
   }.

check_pbkdf2_prf("hmac-" ++ Hash) ->
  case Hash of
    "sha256" -> sha256;
    "sha512" -> sha512;
    _ -> throw({bad_pbkdf2_hash_algo, Hash})
  end;
check_pbkdf2_prf(Prf) ->
  throw({bad_pbkdf2_prf, Prf}).

%% ---- HEX encode/decode
check_hex_to_bin(Param, MaybeHex) ->
  try
    hex_to_bin(MaybeHex)
  catch _:_ ->
    throw({bad_format, "'" ++ Param ++ "' should be hexadecimal"})
  end.

-spec hex_to_bin(Input :: string()) -> binary().
hex_to_bin(S) ->
  hex_to_bin(S, []).
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).

-spec bin_to_hex(Input :: binary()) -> string().
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).
