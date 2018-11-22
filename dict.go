package mnemonic

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
)

// Dictionary stores a wordlist and provides methods to access by index and value
type Dictionary struct {
	dict []string
}

// LoadFromFile loads a wordlist from the specified file
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
		return fmt.Errorf("words in file are not sorted")
	}
	return scanner.Err()
}

// LoadFromArray loads a wordlist from the provided array
func (d *Dictionary) LoadFromArray(words []string) error {
	d.dict = words

	if !sort.StringsAreSorted(d.dict) {
		return fmt.Errorf("words in array are not sorted")
	}

	return nil
}

// DictionaryFromFileOrDie loads a wordlist from the specified file and panics on errors
func DictionaryFromFileOrDie(path string) *Dictionary {
	d := &Dictionary{}
	err := d.LoadFromFile(path)
	if err != nil {
		log.Fatalf("Failed to load dictionary: %v", err)
	}
	return d
}

func DictionaryFromFile(path string) (d *Dictionary, err error) {
	err = d.LoadFromFile(path)
	return
}

// DictionaryFromArrayOrDie loads a wordlist from the provided array and panics on errors
func DictionaryFromArrayOrDie(words []string) *Dictionary {
	d := &Dictionary{}
	err := d.LoadFromArray(words)
	if err != nil {
		log.Fatalf("Failed to load dictionary: %v", err)
	}
	return d
}

// Size Fetch the size of the dictionary
func (d Dictionary) Size() int {
	return len(d.dict)
}

// Word Fetch a word by index
func (d Dictionary) Word(i int) (string, error) {
	if i < 0 || i >= len(d.dict) {
		return "", fmt.Errorf("index %d out of bounds", i)
	}
	return d.dict[i], nil
}

// Index fetches the index of a provided word
func (d Dictionary) Index(word string) (int, error) {
	i := sort.SearchStrings(d.dict, word)
	if i >= len(d.dict) || d.dict[i] != word {
		return -1, fmt.Errorf("word %q not found", word)
	}
	return i, nil
}
