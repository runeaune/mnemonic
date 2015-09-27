package mnemonic

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
)

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

func DictionaryFromFileOrDie(path string) *Dictionary {
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
