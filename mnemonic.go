package mnemonic

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

// ListToString converts a list of strings to a space separated string
func ListToString(list []string) string {
	var buffer bytes.Buffer
	for i, str := range list {
		buffer.WriteString(str)
		if i < len(list)-1 {
			buffer.WriteString(" ")
		}
	}
	return buffer.String()
}

// Mnemonic object
type Mnemonic struct {
	// TODO Add entropy source selection
	dict       *Dictionary
	wordLength int
	lastWords  []string
}

// NewFromFileOrDie generates a mnemonic object based on the words from the
// file provided. Failure to load the words is a fatal error.
func NewFromFileOrDie(path string) *Mnemonic {
	dict := DictionaryFromFileOrDie(path)
	size := dict.Size()
	if size == 0 || size&(size-1) != 0 {
		log.Fatalf("Unsupported dictionary size %d; must be power of two.", size)
	}
	var bits int
	for ; size > 1; size >>= 1 {
		bits++
	}
	return &Mnemonic{
		dict:       dict,
		wordLength: bits,
	}
}

// NewFromArray generates a mnemonic object from the array of provided words
func NewFromArray(words []string) *Mnemonic {
	dict := DictionaryFromArrayOrDie(words)
	size := dict.Size()
	if size == 0 || size&(size-1) != 0 {
		log.Fatalf("unsupported dictionary size %d; must be power of two", size)
	}
	var bits int
	for ; size > 1; size >>= 1 {
		bits++
	}
	return &Mnemonic{
		dict:       dict,
		wordLength: bits,
	}
}

// GenerateFromData generates a mnemonic from the provided data array
func (m *Mnemonic) GenerateFromData(data []byte) ([]string, error) {
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("data length must be divisible by 4 (%d isn't)",
			len(data))
	}
	f := bitFieldFromBytes(data)
	hash := sha256.Sum256(data)
	hashBitCount := uint(len(data) / 4)
	hashBits := uint64(hash[0] >> (8 - hashBitCount))
	f.appendUint(hashBits, hashBitCount)

	// bit_count * (33 / 32) must be a multiple of wordLength
	if (uint(len(data)*8)+hashBitCount)%uint(m.wordLength) != 0 {
		return nil, fmt.Errorf("entropy size not divisible with word length")
	}
	values, err := f.SplitOutWords(m.wordLength)
	if err != nil {
		return nil, fmt.Errorf("failed to divide into words: %v", err)
	}
	words := make([]string, len(values))
	for i, w := range values {
		words[i], err = m.dict.Word(int(w))
		if err != nil {
			return nil, fmt.Errorf("look up dictionary word with index %d: %v",
				w, err)
		}
	}
	m.lastWords = words
	return words, nil

}

// GenerateEntropy generates a list of random words from the loaded dictionary
// corresponding to given number of bits of entropy plus a checksum. The bits
// of entropy must be divisible with 32.
func (m *Mnemonic) GenerateEntropy(bits int) ([]string, error) {
	if bits%32 != 0 {
		return nil, fmt.Errorf("entropy size must be divisible by 32 (%d isn't)",
			bits)
	}
	data := make([]byte, bits/8)
	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed data: %v", err)
	}
	return m.GenerateFromData(data)
}

// GenerateWords generates count random words, corresponding to count *
// dictionary_bits (number of bits of entropy in the dictionary, eg. 11 for a
// dictionary with 2048 words). The count must be divisible with
// 33/dictionary_bits (3 for dictionary with 2048 words).
func (m *Mnemonic) GenerateWords(count int) ([]string, error) {
	entropy := count * m.wordLength
	if entropy%33 != 0 {
		return nil, fmt.Errorf("word count needs to be divisible by %d",
			33/m.wordLength)
	}
	return m.GenerateEntropy(32 * entropy / 33)
}

func (m *Mnemonic) getDataChecksum(words []string) ([]byte, uint64, int, error) {
	f := bitField{}
	for _, word := range words {
		index, err := m.dict.Index(word)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("word not found in dictionary: %v", err)
		}
		f.appendUint(uint64(index), uint(m.wordLength))
	}

	checksumLength := f.Size() / 33
	dataLength := f.Size() - checksumLength
	checksum, err := f.word(dataLength, checksumLength)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to get word from bitfield: %v", err)
	}
	if dataLength%8 != 0 {
		return nil, 0, 0, fmt.Errorf("can't verify checksum on partial bytes")
	}

	data := f.Bytes()
	return data[0 : dataLength/8], checksum, checksumLength, nil
}

// VerifyChecksum checks that the list of words given correspond to data with a
// valid checksum. If this is the case, they were likely generated using the
// BIP-0039 algorithm.
func (m *Mnemonic) VerifyChecksum(words []string) (bool, error) {
	data, checksum, checksumLength, err := m.getDataChecksum(words)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(data)
	hashBits := uint64(hash[0] >> uint(8-checksumLength))
	if hashBits == checksum {
		return true, nil
	}

	return false, nil
}

// SeedFromWordsPassword generates a 512 bit key seed from the word list and
// password provided.
func SeedFromWordsPassword(words []string, password string) []byte {
	return SeedFromPhrasePassword(ListToString(words), password)
}

// SeedFromPhrasePassword generates a 512 bit key seed from the phrase and
// password provided.
func SeedFromPhrasePassword(phrase, password string) []byte {
	salt := []byte("mnemonic" + password)
	return pbkdf2.Key([]byte(phrase), salt, 2048, 64, sha512.New)
}

// GenerateSeedWithPassword generates a 512 bit (64 byte) key based on the last
// generated words and encrypted with a password. If no words have been
// generated, new ones will be generated with 256 bits of entropy.
func (m *Mnemonic) GenerateSeedWithPassword(password string) ([]string, []byte, error) {
	if m.lastWords == nil {
		_, err := m.GenerateEntropy(256)
		if err != nil {
			return nil, nil, fmt.Errorf("Seed generation failed: %v", err)
		}
	}
	seed := SeedFromWordsPassword(m.lastWords, password)
	return m.lastWords, seed, nil
}
