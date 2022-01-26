-module(eaex3_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

read_mnemonic_test() ->
  {ok, Secret} = eaex3:read("test/data/good/23f17984-b3ef-47ce-aed6-55756b8b5249.json", "PASSWORD"),
  ?assertEqual(ed25519_bip39_mnemonic, maps:get(type, Secret)),
  ?assertEqual(<<"not really a mnemonic but who cares">>, maps:get(message, Secret)).

read_masterkey_test() ->
  {ok, Secret} = eaex3:read("test/data/good/e2ac6f2c-5724-47c4-b799-1a58a7e67950.json", "PASSWORD"),
  ?assertEqual(ed25519_slip0010_masterkey, maps:get(type, Secret)),
  ?assertEqual(<<129,202,147,202,135,167,200,243,64,47,71,28,218,251,133,100,
                 187,128,241,104,12,186,31,154,77,162,201,55,141,31,134,238>>, maps:get(message, Secret)).

roundtrip_test_() ->
  Test = fun(Algo) ->
            Key = crypto:strong_rand_bytes(32),
            JSON = eaex3:create_masterkey(Key, "", Algo, "PASSWORD"),
            {ok, Secret} = eaex3:decrypt(JSON, "PASSWORD"),
            ?assertEqual(Key, maps:get(message, Secret))
         end,
  [ fun() -> Test(A) end  || _ <- lists:seq(1, 5), A <- [{pbkdf2, xsalsa20_poly1305}, {argon2id, xsalsa20_poly1305},
                                                         {pbkdf2, chacha20_poly1305}, {argon2id, chacha20_poly1305}] ].

bad_files_test() ->
  ?assertEqual({error, {missing_info,"version"}},
               eaex3:read("test/data/bad/missing_version.json", "PASSWORD")),
  ?assertEqual({error, {bad_version,"Version should be a number (expecting 1)"}},
               eaex3:read("test/data/bad/bad_version.json", "PASSWORD")),
  ?assertEqual({error, {bad_version,"Got version 42 expected 1"}},
               eaex3:read("test/data/bad/wrong_version.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"id"}},
               eaex3:read("test/data/bad/missing_id.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto"}},
               eaex3:read("test/data/bad/missing_crypto.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto/secret_type"}},
               eaex3:read("test/data/bad/missing_secret_type.json", "PASSWORD")),
  ?assertEqual({error, {bad_secret_type,"special-secret"}},
               eaex3:read("test/data/bad/bad_secret_type.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto/symmetric_alg|ciphertext|cipher_params"}},
               eaex3:read("test/data/bad/missing_sym_algo.json", "PASSWORD")),
  ?assertEqual({error, {bad_cipher_algo,"extra-secret-sauce"}},
               eaex3:read("test/data/bad/bad_sym_algo.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto/symmetric_alg|ciphertext|cipher_params"}},
               eaex3:read("test/data/bad/missing_ciphertext.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto/symmetric_alg|ciphertext|cipher_params"}},
               eaex3:read("test/data/bad/missing_cipher_params.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto/cipher_params/nonce"}},
               eaex3:read("test/data/bad/missing_nonce.json", "PASSWORD")),
  ?assertEqual({error, {bad_format,"'crypto/cipher_params/nonce' should be hexadecimal"}},
               eaex3:read("test/data/bad/bad_nonce.json", "PASSWORD")),
  ?assertEqual({error, {bad_format,"'crypto/ciphertext' should be hexadecimal"}},
               eaex3:read("test/data/bad/bad_ciphertext.json", "PASSWORD")),
  ?assertEqual({error, {missing_info,"crypto/kdf|kdf_params"}},
               eaex3:read("test/data/bad/missing_kdf.json", "PASSWORD")),
  ?assertEqual({error, {bad_kdf,"not-a-kdf"}},
               eaex3:read("test/data/bad/bad_kdf.json", "PASSWORD")),
  ?assertEqual({error, {bad_kdf_params,"Expected: memlimit_kib, opslimit and salt"}},
               eaex3:read("test/data/bad/bad_kdf_params.json", "PASSWORD")),
  ?assertEqual({error, {bad_kdf_params,"Expected: c, dklen, prf and salt"}},
               eaex3:read("test/data/bad/bad_kdf_params2.json", "PASSWORD")),
  ?assertEqual({error, {bad_format,"'crypto/kdf_params/salt' should be hexadecimal"}},
               eaex3:read("test/data/bad/bad_salt.json", "PASSWORD")),
  ok.
