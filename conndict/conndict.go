package conndict

import (
	"bufio"
	"fmt"
	"github.com/untangle/packetd/support"
	"os"
	"strings"
	"sync"
)

const pathBase string = "/proc/net/dict"

var readMutex = &sync.Mutex{}
var appname = "conndict"

//-----------------------------------------------------------------------------

// DictPair holds a field value pair of data
type DictPair struct {
	Field string
	Value string
}

//-----------------------------------------------------------------------------

// Create a field/value pair from a line of output from /proc/net/dict/*
func parsePair(line string) DictPair {
	slices := strings.SplitN(line, ": ", 2)
	pair := DictPair{Field: slices[0], Value: slices[1]}
	return pair
}

//-----------------------------------------------------------------------------

// Print a pair's field and value
func (p DictPair) Print() {
	support.LogMessage(support.LogInfo, appname, "Field: %s Value: %s\n", p.Field, p.Value)
}

//-----------------------------------------------------------------------------

// SetPair sets a field/value pair for the supplied conntrack id
func SetPair(field string, value string, id uint) error {
	file, err := os.OpenFile(pathBase+"/write", os.O_WRONLY, 0660)
	setstr := fmt.Sprintf("id=%d,field=%s,value=%s", id, field, value)

	if err != nil {
		return fmt.Errorf("conndict: SetPair: Failed to open %s", pathBase+"/write")
	}

	defer file.Close()

	_, err = file.WriteString(setstr)
	if err != nil {
		return fmt.Errorf("conndict: SetPair: Failed to write %s", setstr)
	}

	file.Sync()

	return err
}

//-----------------------------------------------------------------------------

// SetPairs sets a slice of field/value pairs for the supplied conntrack id
func SetPairs(pairs []DictPair, id uint) error {
	for _, p := range pairs {
		err := SetPair(p.Field, p.Value, id)

		if err != nil {
			support.LogMessage(support.LogErr, appname, "SetPairs failed on setting %s:%s for %d\n", p.Field, p.Value, id)
			return (err)
		}
	}

	return nil
}

//-----------------------------------------------------------------------------

// GetPairs gets all of the field/value pairs for the supplied conntrack id
func GetPairs(id uint) ([]DictPair, error) {
	file, err := os.OpenFile(pathBase+"/read", os.O_RDWR, 0660)
	setstr := fmt.Sprintf("%d", id)

	if err != nil {
		return nil, fmt.Errorf("conndict: Get_pairs: Failed to open %s", pathBase+"/read")
	}

	defer file.Close()

	readMutex.Lock()
	_, err = file.WriteString(setstr)

	if err != nil {
		return nil, fmt.Errorf("conndict: GetPair: Failed to write %s", setstr)
	}

	file.Sync()

	var pairs []DictPair

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pairs = append(pairs, parsePair(scanner.Text()))
	}
	readMutex.Unlock()
	return pairs, err
}

//-----------------------------------------------------------------------------

// GetAll gets all of the field/value pairs for all known conntrack entries
func GetAll() ([]DictPair, error) {
	file, err := os.OpenFile(pathBase+"/all", os.O_RDWR, 0660)

	if err != nil {
		return nil, fmt.Errorf("conndict: Get_pairs: Failed to open %s", pathBase+"/all")
	}

	defer file.Close()

	var pairs []DictPair

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pairs = append(pairs, parsePair(scanner.Text()))
	}
	return pairs, err
}

//-----------------------------------------------------------------------------
