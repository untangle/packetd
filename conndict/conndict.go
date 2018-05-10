package conndict

import "bufio"
import "fmt"
import "os"
import "strings"
import "sync"

const path_base string = "/proc/net/dict"

var read_mutex = &sync.Mutex{}

type Pair struct {
	Field string
	Value string
}

// Create a field/value pair from a line of output from /proc/net/dict/*
func parse_pair(line string) Pair {
	slices := strings.SplitN(line, ": ", 2)
	new_pair := Pair{Field: slices[0], Value: slices[1]}
	return new_pair
}

// Print a pair's field and value
func (p Pair) Print() {
	fmt.Printf("Field: %s Value: %s\n", p.Field, p.Value)
}

// Set a field/value pair based on the supplied conntrack id
func Set_pair(field string, value string, id uint) error {
	file, err := os.OpenFile(path_base+"/write", os.O_WRONLY, 0660)
	set_string := fmt.Sprintf("id=%d,field=%s,value=%s", id, field, value)

	if err != nil {
		return fmt.Errorf("conndict: Set_pair: Failed to open %s", path_base+"/write")
	}

	defer file.Close()

	_, err = file.WriteString(set_string)
	if err != nil {
		return fmt.Errorf("conndict: Set_pair: Failed to write %s", set_string)
	}

	file.Sync()

	return err
}

// Set a slice of field/value pairs based on the supplied conntrack id
func Set_pairs(pairs []Pair, id uint) error {
	for _, p := range pairs {
		err := Set_pair(p.Field, p.Value, id)

		if err != nil {
			fmt.Println(err)
			return fmt.Errorf("conndict: Set_pairs: Failed on setting %s:%s for %d", p.Field, p.Value, id)
		}
	}

	return nil
}

// Get all of the field/value pairs associated with the supplied conntrack id
func Get_pairs(id uint) ([]Pair, error) {
	file, err := os.OpenFile(path_base+"/read", os.O_RDWR, 0660)
	set_string := fmt.Sprintf("%d", id)

	if err != nil {
		return nil, fmt.Errorf("conndict: Get_pairs: Failed to open %s", path_base+"/read")
	}

	defer file.Close()

	read_mutex.Lock()
	_, err = file.WriteString(set_string)

	if err != nil {
		return nil, fmt.Errorf("conndict: Set_pair: Failed to write %s", set_string)
	}

	file.Sync()

	var pairs []Pair

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pairs = append(pairs, parse_pair(scanner.Text()))
	}
	read_mutex.Unlock()
	return pairs, err
}

// Get all of the field/value pairs for all known conntrack entries
func Get_all() ([]Pair, error) {
	file, err := os.OpenFile(path_base+"/all", os.O_RDWR, 0660)

	if err != nil {
		return nil, fmt.Errorf("conndict: Get_pairs: Failed to open %s", path_base+"/all")
	}

	defer file.Close()

	var pairs []Pair

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pairs = append(pairs, parse_pair(scanner.Text()))
	}
	return pairs, err
}
