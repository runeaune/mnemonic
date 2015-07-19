package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/aarbt/bitcoin-mnemonic"
)

var entropySize = flag.Int("entropy_size", 256, "Number of bits of entropy used to generate phrase. Must be multiple of 32. Defaults to 256.")
var wordCount = flag.Int("word_count", 0, "Number of bits of entropy used to generate phrase. Must be multiple of 32. Defaults to 256.")
var wordFile = flag.String("word_file", "wordlist.txt", "A file containing the dictionary to use. One word per line, 2048 in total.")
var password = flag.String("password", "", "Password used to encrypt key (optional).")

func main() {
	flag.Parse()

	fmt.Printf("Generating seed words and key.\n")
	if *password != "" {
		fmt.Printf("Using password %q.\n", *password)
	} else {
		fmt.Printf("Not using any password.\n")
	}
	m := mnemonic.NewMnemonicWithWordfileOrDie(*wordFile)

	var err error
	if *wordCount != 0 {
		_, err = m.GenerateWords(*wordCount)
	} else {
		_, err = m.GenerateEntropy(*entropySize)
	}
	if err != nil {
		log.Fatalf("Failed to generate seed words: %v\n", err)
	}
	words, key, err := m.GenerateSeedWithPassword(*password)
	if err != nil {
		log.Fatalf("Failed to generate seed: %v\n", err)
		log.Fatal(err)
	}
	fmt.Printf("Seed words (%d): %q\nKey (512 bits): %s\n",
		len(words), mnemonic.ListToString(words), hex.EncodeToString(key))
}
