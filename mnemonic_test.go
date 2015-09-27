package mnemonic_test

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/aarbt/mnemonic"
	"testing"
)

type testSet struct {
	English [][]string
}

func TestDictionaryLookup(t *testing.T) {
	dict := mnemonic.DictionaryFromFileOrDie("wordlist.txt")
	if dict.Size() != 2048 {
		t.Fatalf("Unexpected dictionary size: %d", dict.Size())
	}
	indexes := []int{0, 32, 2047, 765, 100, 1000, 1}
	words := []string{"abandon", "advice", "zoo", "garden", "arrive", "laptop", "ability"}
	for i, index := range indexes {
		word, err := dict.Word(index)
		if err != nil {
			t.Fatalf("Failed to look up word %d: %v", index, err)
		}
		if word != words[i] {
			t.Errorf("Word mismatch; expected %q, got %q.", words[i], word)
		}
		j, err := dict.Index(word)
		if err != nil {
			t.Fatalf("Failed to get word index for %q: %v", word, err)
		}
		if j != index {
			t.Errorf("Index mismatch; expected %q, got %q.", index, j)
		}
	}
}

func TestMnemonicGeneration(t *testing.T) {
	m := mnemonic.NewFromFileOrDie("wordlist.txt")
	file, err := ioutil.ReadFile("test_vectors.json")
	if err != nil {
		t.Fatalf("File error: %v\n", err)
	}

	var tests testSet
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("File parsing error: %v\n", err)
	}

	for i, test := range tests.English {
		data, err := hex.DecodeString(test[0])
		if err != nil {
			t.Fatalf("Test %d: Failed to decode hex encoded data %q: %v",
				i, test[0], err)
		}
		words, err := m.GenerateFromData(data)
		if err != nil {
			t.Fatalf("Test %d: Failed to generator words: %v", i, err)
		}
		str := mnemonic.ListToString(words)
		if str != test[1] {
			t.Errorf("Test %d: Words don't match: Got %q, expected %q.",
				i, str, test[1])
		}
		res, err := m.VerifyChecksum(strings.Split(str, " "))
		if err != nil {
			t.Fatalf("Test %d: Failed to verify checksum: %v", i, err)
		}
		if !res {
			t.Fatalf("Test %d: Checksum mismatch.", i)
		}

		_, key, err := m.GenerateSeedWithPassword("TREZOR")
		if err != nil {
			t.Fatalf("Test %d: Failed to generator seed: %v", i, err)
		}
		encoded := hex.EncodeToString(key)
		if encoded != test[2] {
			t.Errorf("Test %d: Key doesn't match: Got %q, expected %q.",
				i, encoded, test[2])
		}

	}
}
