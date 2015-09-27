package mnemonic

import (
	"fmt"
)

type bitField struct {
	b    []byte
	size int
}

func bitFieldFromBytes(b []byte) *bitField {
	return &bitField{
		b:    b,
		size: len(b) * 8,
	}
}

func (f *bitField) appendUint(val uint64, size uint) {
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

func (f bitField) bit(i uint) bool {
	b := f.b[i/8]
	filter := byte(1 << (7 - (i % 8)))
	if b&filter == 0 {
		return false
	} else {
		return true
	}
}

func (f bitField) word(i, length int) (uint64, error) {
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
		if f.bit(uint(i)) {
			val += (1 << uint(length))
		}
		i++
	}
	return val, nil
}

func (f bitField) SplitOutWords(length int) ([]uint64, error) {
	var list []uint64
	for i := 0; i < f.size; i += length {
		word, err := f.word(i, length)
		if err != nil {
			return nil, fmt.Errorf("Failed to get word number %d: %v", i, err)
		}
		list = append(list, word)
	}
	return list, nil
}

func (f bitField) Size() int {
	return f.size
}

func (f bitField) Bytes() []byte {
	return f.b
}

func (f bitField) String() string {
	str := ""
	for i := 0; i < f.size; i++ {
		if f.bit(uint(i)) {
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
