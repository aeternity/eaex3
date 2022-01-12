eaex3
=====

An Erlang library for working with Aeternity Secret storage format
[AEX-3](https://github.com/aeternity/AEXs/blob/master/AEXS/aex-3.md)

Usage
-----

`eaex3:store_mnemonic/4` and `eaex3:store_masterkey/4` will create a JSON-file
containing a secretly stored BIP39 mnemonic and SLIP10 masterkey respectively.

`eaex3:read/2` will read the secret information back from disk.

See the [AEX-3
spec](https://github.com/aeternity/AEXs/blob/master/AEXS/aex-3.md) for details.


Build
-----

    $ rebar3 compile
