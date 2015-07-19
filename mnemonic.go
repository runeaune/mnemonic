package mnemonic

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"os"
	"sort"

	"golang.org/x/crypto/pbkdf2"
)

type BitField struct {
	b    []byte
	size int
}

func NewBitFieldFromBytes(b []byte) *BitField {
	return &BitField{
		b:    b,
		size: len(b) * 8,
	}
}

func (f *BitField) AppendUint(val uint64, size uint) {
	for size > 0 {
		spare := uint(len(f.b)*8 - f.size)

		// Field is out of space, allocate another byte.
		if spare == 0 {
			f.b = append(f.b, 0)
			spare = 8
		}

		bits := val
		length := size
		if spare < size {
			// We don't have room for all the bits on this round.
			length = spare
			bits >>= (size - spare)
		}

		i := len(f.b) - 1
		f.b[i] = f.b[i] | (byte(bits) << (spare - length))

		// Filter out the bits just appended to the field.
		val &= 1<<(size-length) - 1
		size -= length
		f.size += int(length)
	}
}

func (f BitField) Bit(i uint) bool {
	b := f.b[i/8]
	filter := byte(1 << (7 - (i % 8)))
	if b&filter == 0 {
		return false
	} else {
		return true
	}
}

func (f BitField) Word(i, length int) (uint64, error) {
	// TODO optimize this function.
	var val uint64
	if i < 0 {
		return 0, fmt.Errorf("Index %d not supported, must be zero or positive.", i)
	}
	if length < 1 || length > 32 {
		return 0, fmt.Errorf("Length %d not supported, must be between 1 and 32 inclusive.",
			length)
	}
	if i+length > f.size {
		return 0, fmt.Errorf("Index + length is out of bounds (%d + %d > %d.",
			i, length, f.size)
	}
	for length > 0 {
		length--
		if f.Bit(uint(i)) {
			val += (1 << uint(length))
		}
		i++
	}
	return val, nil
}

func (f BitField) SplitOutWords(length int) ([]uint64, error) {
	var list []uint64
	for i := 0; i < f.size; i += length {
		word, err := f.Word(i, length)
		if err != nil {
			return nil, fmt.Errorf("Failed to get word number %d: %v", i, err)
		}
		list = append(list, word)
	}
	return list, nil
}

func (f BitField) Size() int {
	return f.size
}

func (f BitField) Bytes() []byte {
	return f.b
}

func (f BitField) String() string {
	str := ""
	for i := 0; i < f.size; i++ {
		if f.Bit(uint(i)) {
			str = str + "1"
		} else {
			str = str + "0"
		}
		if i%4 == 3 {
			str = str + " "
		}
	}
	return str
}

type Dictionary struct {
	dict []string
}

func (d *Dictionary) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		d.dict = append(d.dict, scanner.Text())
	}
	if !sort.StringsAreSorted(d.dict) {
		return fmt.Errorf("Words in file are not sorted.")
	}
	return scanner.Err()
}

func NewDictionaryFromFileOrDie(path string) *Dictionary {
	d := &Dictionary{}
	err := d.LoadFromFile(path)
	if err != nil {
		log.Fatal("Failed to load dictionary: %v", err)
	}
	return d
}

func (d Dictionary) Size() int {
	return len(d.dict)
}

func (d Dictionary) Word(i int) (string, error) {
	if i < 0 || i >= len(d.dict) {
		return "", fmt.Errorf("Index %d out of bounds.", i)
	}
	return d.dict[i], nil
}

func (d Dictionary) Index(word string) (int, error) {
	i := sort.SearchStrings(d.dict, word)
	if i >= len(d.dict) || d.dict[i] != word {
		return -1, fmt.Errorf("Word %q not found.", word)
	}
	return i, nil
}

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

type Mnemonic struct {
	// TODO Add entropy source selection
	dict       *Dictionary
	wordLength int
	lastWords  []string
}

func NewMnemonicWithWordfileOrDie(path string) *Mnemonic {
	dict := NewDictionaryFromFileOrDie(path)
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

func (m *Mnemonic) GenerateFromData(data []byte) ([]string, error) {
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("Data length must be divisible by 4 (%d isn't).",
			len(data))
	}
	f := NewBitFieldFromBytes(data)
	hash := sha256.Sum256(data)
	hashBitCount := uint(len(data) / 4)
	hashBits := uint64(hash[0] >> (8 - hashBitCount))
	f.AppendUint(hashBits, hashBitCount)

	// bit_count * (33 / 32) must be a multiple of wordLength
	if (uint(len(data)*8)+hashBitCount)%uint(m.wordLength) != 0 {
		return nil, fmt.Errorf("Entropy size not divisible with word length.")
	}
	vals, err := f.SplitOutWords(m.wordLength)
	if err != nil {
		return nil, fmt.Errorf("Failed to divide into words: %v", err)
	}
	words := make([]string, len(vals))
	for i, w := range vals {
		words[i], err = m.dict.Word(int(w))
		if err != nil {
			return nil, fmt.Errorf("Look up dictionary word with index %d: %v",
				w, err)
		}
	}
	m.lastWords = words
	return words, nil

}

func (m *Mnemonic) GenerateEntropy(bits int) ([]string, error) {
	if bits%32 != 0 {
		return nil, fmt.Errorf("Entropy size must be divisible by 32 (%d isn't).",
			bits)
	}
	data := make([]byte, bits/8)
	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate seed data: %v", err)
	}
	return m.GenerateFromData(data)
}

func (m *Mnemonic) GenerateWords(count int) ([]string, error) {
	entropy := count * m.wordLength
	if entropy%33 != 0 {
		return nil, fmt.Errorf("Word count needs to be divisible by %d.",
			33/m.wordLength)
	}
	return m.GenerateEntropy(32 * entropy / 33)
}

func (m *Mnemonic) VerifyChecksum(words []string) (bool, error) {
	f := BitField{}
	for _, word := range words {
		index, err := m.dict.Index(word)
		if err != nil {
			return false, fmt.Errorf("Word not found in dictionary: %v", err)
		}
		f.AppendUint(uint64(index), uint(m.wordLength))
	}

	checksumLength := f.Size() / 33
	dataLength := f.Size() - checksumLength
	checksum, err := f.Word(dataLength, checksumLength)
	if err != nil {
		return false, fmt.Errorf("Failed to get word from bitfield: %v", err)
	}
	if dataLength%8 != 0 {
		return false, fmt.Errorf("Can't verify checksum on partial bytes.")
	}

	data := f.Bytes()
	hash := sha256.Sum256(data[0 : dataLength/8])
	hashBits := uint64(hash[0] >> uint(8-checksumLength))
	if hashBits == checksum {
		return true, nil
	} else {
		return false, nil
	}
}

// Generate a 512 bit (64 byte) key based on the last generated words and
// encrypted with a password. If no words have been generated, new ones will
// be generated with 256 bits of entropy.
func (m *Mnemonic) GenerateSeedWithPassword(password string) ([]string, []byte, error) {
	if m.lastWords == nil {
		_, err := m.GenerateEntropy(256)
		if err != nil {
			return nil, nil, fmt.Errorf("Seed generation failed: %v", err)
		}
	}
	phrase := []byte(ListToString(m.lastWords))
	salt := []byte("mnemonic" + password)
	return m.lastWords, pbkdf2.Key(phrase, salt, 2048, 64, sha512.New), nil
}
