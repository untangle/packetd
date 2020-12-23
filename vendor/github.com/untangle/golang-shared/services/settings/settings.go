package settings

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/untangle/golang-shared/services/logger"
)

const settingsFile = "/etc/config/settings.json"
const defaultsFile = "/etc/config/defaults.json"
const currentFile = "/etc/config/current.json"

// Startup settings service
func Startup() {
}

// Shutdown settings service
func Shutdown() {

}

// GetCurrentSettings returns the current settings from the specified path
// the current settings are the settings after being synced
func GetCurrentSettings(segments []string) (interface{}, error) {
	// for backwards compatibility before we saved current.json
	// if it does not exist, just read settings.json
	// XXX this should be removed at some point in the future
	if _, err := os.Stat(currentFile); os.IsNotExist(err) {
		return GetSettingsFile(segments, settingsFile)
	}
	return GetSettingsFile(segments, currentFile)
}

// GetSettings returns the settings from the specified path
func GetSettings(segments []string) (interface{}, error) {
	return GetSettingsFile(segments, settingsFile)
}

// SetSettings updates the settings
func SetSettings(segments []string, value interface{}, force bool) (interface{}, error) {
	return SetSettingsFile(segments, value, settingsFile, force)
}

// TrimSettings trims the settings
func TrimSettings(segments []string) (interface{}, error) {
	return TrimSettingsFile(segments, settingsFile)
}

// GetDefaultSettings returns the default settings from the specified path
func GetDefaultSettings(segments []string) (interface{}, error) {
	return GetSettingsFile(segments, defaultsFile)
}

// GetSettingsFile returns the settings from the specified path of the specified filename
func GetSettingsFile(segments []string, filename string) (interface{}, error) {
	var err error
	var jsonObject interface{}

	jsonObject, err = readSettingsFileJSON(filename)
	if err != nil {
		return createJSONErrorObject(err), err
	}

	jsonObject, err = getSettingsFromJSON(jsonObject, segments)
	if err != nil {
		return createJSONErrorObject(err), err
	}

	return jsonObject, nil
}

// SetSettingsFile updates the settings
func SetSettingsFile(segments []string, value interface{}, filename string, force bool) (interface{}, error) {
	var ok bool
	var err error
	var jsonSettings map[string]interface{}
	var newSettings interface{}

	jsonSettings, err = readSettingsFileJSON(filename)
	if err != nil {
		return createJSONErrorObject(err), err
	}

	newSettings, err = setSettingsInJSON(jsonSettings, segments, value)
	if err != nil {
		return createJSONErrorObject(err), err
	}
	jsonSettings, ok = newSettings.(map[string]interface{})
	if !ok {
		err = errors.New("Invalid global settings object")
		return createJSONErrorObject(err), err
	}

	output, err := syncAndSave(jsonSettings, filename, force)
	if err != nil {
		return map[string]interface{}{"error": err.Error(), "output": output}, err
	}

	return map[string]interface{}{"result": "OK", "output": output}, err
}

// readSettingsFileJSON reads the settings file and return the corresponding JSON object
func readSettingsFileJSON(filename string) (map[string]interface{}, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var jsonObject interface{}
	err = json.Unmarshal(raw, &jsonObject)
	if err != nil {
		return nil, err
	}
	j, ok := jsonObject.(map[string]interface{})
	if ok {
		return j, nil
	}

	return nil, errors.New("Invalid settings file format")
}

// writeSettingsFileJSON writes the specified JSON object to the settings file
func writeSettingsFileJSON(jsonObject map[string]interface{}, file *os.File) (bool, error) {
	var err error

	// Marshal it back to a string (with ident)
	var jsonBytes []byte
	jsonBytes, err = json.MarshalIndent(jsonObject, "", "  ")
	if err != nil {
		return false, err
	}

	_, err = file.Write(jsonBytes)
	if err != nil {
		return false, err
	}
	file.Sync()

	return true, nil
}

// Create a JSON object with the single key value pair
func createJSONObject(key string, value string) map[string]interface{} {
	return map[string]interface{}{key: value}
}

// Create a JSON object with an error based on the object
func createJSONErrorObject(e error) map[string]interface{} {
	return createJSONObject("error", e.Error())
}

// getArrayIndex get an array value by index as a string
func getArrayIndex(array []interface{}, idx string) (interface{}, error) {
	i, err := strconv.Atoi(idx)
	if err != nil {
		return nil, err
	}
	if i >= cap(array) {
		return nil, errors.New("array index exceeded capacity")
	}
	return array[i], nil
}

// setArray index sets the value of element specified by the idx as a string
// to the specified value
func setArrayIndex(array []interface{}, idx string, value interface{}) ([]interface{}, error) {
	i, err := strconv.Atoi(idx)
	if err != nil {
		return nil, err
	}
	if i >= cap(array) {
		return nil, errors.New("array index exceeded capacity")
	}
	array[i] = value
	return array, nil
}

// getObjectIndex takes an object that is either a []interface{} or map[string]interface{}
// and returns the object specified by the index string
func getObjectIndex(obj interface{}, idx string) (interface{}, error) {
	var jsonObject map[string]interface{}
	var jsonArray []interface{}
	var ok bool
	jsonObject, ok = obj.(map[string]interface{})
	if ok {
		return jsonObject[idx], nil
	}
	jsonArray, ok = obj.([]interface{})
	if ok {
		return getArrayIndex(jsonArray, idx)
	}
	return nil, fmt.Errorf("unknown type: %T", obj)
}

// setObjectIndex takes an object that is either a []interface{} or map[string]interface{}
// and a index as a string, and returns the child object
// if the object is an array the index must be a string integer "3"
// if the object is an jsonobject the index can be any string
func setObjectIndex(obj interface{}, idx string, value interface{}) (interface{}, error) {
	var jsonObject map[string]interface{}
	var jsonArray []interface{}
	var ok bool
	jsonObject, ok = obj.(map[string]interface{})
	if ok {
		jsonObject[idx] = value
		return jsonObject, nil
	}
	jsonArray, ok = obj.([]interface{})
	if ok {
		return setArrayIndex(jsonArray, idx, value)
	}
	return nil, errors.New("unknown type")
}

// TrimSettingsFile trims the settings in the specified file
func TrimSettingsFile(segments []string, filename string) (interface{}, error) {
	var ok bool
	var err error
	var iterJSONObject map[string]interface{}
	var jsonSettings map[string]interface{}

	if segments == nil {
		err = errors.New("Invalid trim settings path")
		return createJSONErrorObject(err), err
	}

	jsonSettings, err = readSettingsFileJSON(filename)
	if err != nil {
		return createJSONErrorObject(err), err
	}

	iterJSONObject = jsonSettings

	for i, value := range segments {
		//if this is the last value, set and break
		if i == len(segments)-1 {
			delete(iterJSONObject, value)
			break
		}

		// otherwise recurse down object
		// 3 cases:
		// if json[foo] does not exist, nothing to delete
		// if json[foo] exists and is a map, recurse
		// if json[foo] exists and is not a map (its some value)
		//    in this case we throw an error
		if iterJSONObject[value] == nil {
			// path does not exists - nothing to delete, just quit
			break
		} else {
			var j map[string]interface{}
			j, ok = iterJSONObject[value].(map[string]interface{})
			iterJSONObject[value] = make(map[string]interface{})
			if ok {
				iterJSONObject[value] = j
				iterJSONObject = j // for next iteration
			} else {
				err = errors.New("Non-dict found in path: " + string(value))
				return createJSONErrorObject(err), err
			}
		}
	}

	output, err := syncAndSave(jsonSettings, filename, false)
	if err != nil {
		return map[string]interface{}{"error": err.Error(), "output": output}, err
	}

	return map[string]interface{}{"result": "OK", "output": output}, err
}

// setSettingsInJSON sets the value attribute specified of the segments path to the specified value
func setSettingsInJSON(jsonObject interface{}, segments []string, value interface{}) (interface{}, error) {
	var err error

	if len(segments) == 0 {
		// the value is the new jsonObject
		return value, nil
	} else if len(segments) == 1 {
		return setObjectIndex(jsonObject, segments[0], value)
	} else {
		element, newSegments := segments[0], segments[1:]

		mapObject, ok := jsonObject.(map[string]interface{})

		// if this element isnt a map, we cant recurse, so just make it a map
		// this will override the existing value
		if !ok {
			mapObject = make(map[string]interface{})
			jsonObject = mapObject
		}

		// if the next element is null null, create a new map
		if mapObject[element] == nil {
			mapObject[element] = make(map[string]interface{})
		}

		mapObject[element], err = setSettingsInJSON(mapObject[element], newSegments, value)
		return jsonObject, err
	}
}

// getSettingsFromJSON gets the value attribute specified by the segments string from the specified json object
func getSettingsFromJSON(jsonObject interface{}, segments []string) (interface{}, error) {
	if len(segments) == 0 {
		return jsonObject, nil
	} else if len(segments) == 1 {
		return getObjectIndex(jsonObject, segments[0])
	} else {
		element, newSegments := segments[0], segments[1:]

		newObject, err := getObjectIndex(jsonObject, element)
		if err != nil {
			return nil, err
		}
		if newObject == nil {
			return nil, errors.New("Attribute " + element + " missing from JSON Object")
		}
		return getSettingsFromJSON(newObject, newSegments)
	}
}

// runSyncSettings runs sync-settings on the specified filename
func runSyncSettings(filename string, force bool) (string, error) {
	cmd := exec.Command("/usr/bin/sync-settings", "-o", "openwrt", "-f", filename, "-v", "force="+strconv.FormatBool(force))
	outbytes, err := cmd.CombinedOutput()
	output := string(outbytes)
	if err != nil {
		// if just a non-zero exit code, just use standard language
		// otherwise use the real error message
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() != 0 {
					logger.Warn("Failed to run sync-settings: %v\n", err.Error())
					return output, errors.New("Failed to save settings")
				}
			}
		}
		logger.Warn("Failed to run sync-settings: %v\n", err.Error())
		return output, err
	}
	return output, nil
}

// syncAndSave writes the jsonObject to a tmp file
// calls sync-settings on the tmp file, and if the sync-settings returns 0
// it copies the tmp file to the destination specified in filename
// if sync-settings does not succeed it returns the error and output
// returns stdout, stderr, and an error
func syncAndSave(jsonObject map[string]interface{}, filename string, force bool) (string, error) {
	tmpfile, err := tempFile("", "settings.json.")
	if err != nil {
		logger.Warn("Failed to generate tmpfile: %v\n", err.Error())
		return "Failed to generate tmpfile.", err
	}
	defer tmpfile.Close()

	logger.Info("Writing settings to %v\n", tmpfile.Name())
	_, syncError := writeSettingsFileJSON(jsonObject, tmpfile)
	if syncError != nil {
		logger.Warn("Failed to write settings file: %v\n", err.Error())
		return "Failed to write settings.", err
	}

	output, err := runSyncSettings(tmpfile.Name(), force)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		logger.Info("sync-settings: %v\n", scanner.Text())
	}
	if err != nil {
		logger.Warn("sync-settings return an error: %v\n", err.Error())
		return output, err
	}

	logger.Info("Copy settings from %v to  %v\n", tmpfile.Name(), filename)
	outfile, err := os.Create(filename)
	if err != nil {
		return output, err
	}
	defer outfile.Close()

	tmpfile.Seek(0, 0) // go back to start of file
	_, err = io.Copy(outfile, tmpfile)
	if err != nil {
		logger.Warn("Failed to copy file: %v\n", err.Error())
		return output, err
	}

	return output, nil
}

// tempFile is similar to ioutil.TempFile
// except with more permissive permissions
func tempFile(dir, pattern string) (f *os.File, err error) {
	if dir == "" {
		dir = os.TempDir()
	}

	var prefix, suffix string
	if pos := strings.LastIndex(pattern, "*"); pos != -1 {
		prefix, suffix = pattern[:pos], pattern[pos+1:]
	} else {
		prefix = pattern
	}

	for i := 0; i < 10000; i++ {
		name := filepath.Join(dir, prefix+strconv.FormatInt(time.Now().Unix()-int64(i), 10)+suffix)
		f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
		if os.IsExist(err) {
			continue
		}
		break
	}
	return
}

// GetUID returns the UID of the system
func GetUID() (string, error) {
	file, err := os.Open("/etc/config/uid")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		return scanner.Text(), nil
	}
	return "", errors.New("UID file missing contents")
}
