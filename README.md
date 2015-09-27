# Bitcoin Mnemonic (BIP-0039)
Functions for generating random seeds and representing them as dictionary words according to BIP-0039 (Mnemonic code for generating deterministic keys -- https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). The word list can be used to recover the generated seed, potentially requiring a password.

```
m := mnemonic.NewMnemonicWithWordfileOrDie("wordlist.txt")
m.GenerateEntropy(128)
words, key, err := m.GenerateSeedWithPassword("aPassword")
fmt.Println(mnemonic.ListToString(words))
```

`words` will be an array of strings, and ListToString() will turn that into a single string:
`also twelve mirror crumble above pretty debate review outside require tribe flight`

The generated key can later be regenerated from the word list:
```
key := mnemonic.SeedFromWordsPassword("aPassword")
```

# Short, memorable nickname for key (or data)
Simple function for representing arbitrary data as a memorable (animal based) string. The generated string can not be used to recover any part of the original data.

```
data, _ := hex.DecodeString("212af859c35b20005791182866be2a6f")
fmt.Println(mnemonic.Nickname(data))
```
The resulting nickname will be `famous seal 642`
