package settings

import (
	"encoding/json"
	"errors"
	"github.com/untangle/packetd/services/logger"
	"io/ioutil"
	"strconv"
)

// settings stores the current system settings
var settings map[string]interface{}

// Startup initializes all settings objects
func Startup() {
	var err error
	settings, err = readSettingsFileJSON()
	if err != nil {
		logger.Warn("Error reading settings file: %s\n", err.Error())
	}
	if settings == nil {
		logger.Err("Failed to read settings file.\n")
	}

	// jsonString, err := json.MarshalIndent(settings, "", "  ")
	// if err != nil {
	// logger.Warn("Error reading settings file: %s\n", err.Error())
	// } else {
	// logger.Debug("settings: %s\n", jsonString)
	// }
}

// Shutdown settings service
func Shutdown() {

}

// GetSettings returns the daemon settings
func GetSettings(segments []string) interface{} {
	var ok bool
	var err error
	var jsonObject map[string]interface{}
	var jsonArray []interface{}

	jsonObject, err = readSettingsFileJSON()
	if err != nil {
		return createJSONErrorObject(err)
	}
	for i, value := range segments {
		if value != "" {
			var j interface{}
			if jsonObject != nil {
				j = jsonObject[value]
			} else if jsonArray != nil {
				j, err = getArrayIndex(jsonArray, value)
				if err != nil {
					return err
				}
			}

			if j == nil {
				return createJSONErrorString("Attribute " + value + " not found in JSON object")
			}
			// if final
			if i == (len(segments) - 1) {
				return j
			}
			// if not final, it must be either a json object or an array
			// set jsonObject if object or jsonArray if array and recurse
			jsonObject, ok = j.(map[string]interface{})
			if ok {
				jsonArray = nil
				continue
			} else {
				jsonArray, ok = j.([]interface{})
				if ok {
					jsonObject = nil
					continue
				} else {
					return createJSONErrorString("Cast error")
				}
			}
		}
	}

	return jsonObject
}

// SetSettingsParse updates the daemon settings from a parsed JSON object
func SetSettingsParse(segments []string, byteSlice []byte) interface{} {
	var err error
	var bodyJSONObject interface{}

	err = json.Unmarshal(byteSlice, &bodyJSONObject)
	if err != nil {
		return createJSONErrorObject(err)
	}

	return SetSettings(segments, bodyJSONObject)
}

// SetSettings updates the daemon settings
func SetSettings(segments []string, value interface{}) interface{} {
	var ok bool
	var err error
	var jsonSettings map[string]interface{}
	var newJsonSettings interface{}

	jsonSettings, err = readSettingsFileJSON()
	if err != nil {
		return createJSONErrorObject(err)
	}

	newJsonSettings, err = setSettings(jsonSettings, segments, value)
	if err != nil {
		return createJSONErrorObject(err)
	}
	jsonSettings, ok = newJsonSettings.(map[string]interface{})
	if !ok {
		return createJSONErrorObject(errors.New("Invalid global settings object"))
	}

	_, err = writeSettingsFileJSON(jsonSettings)
	if err != nil {
		return createJSONErrorObject(err)
	}

	return createJSONObject("result", "OK")
}

// TrimSettings trims the settings
func TrimSettings(segments []string) interface{} {
	var ok bool
	var err error
	var iterJSONObject map[string]interface{}
	var jsonSettings map[string]interface{}

	if segments == nil {
		return createJSONErrorString("Invalid trim settings path")
	}

	jsonSettings, err = readSettingsFileJSON()
	if err != nil {
		return createJSONErrorObject(err)
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
				return createJSONErrorString("Non-dict found in path: " + string(value))
			}
		}
	}

	_, err = writeSettingsFileJSON(jsonSettings)
	if err != nil {
		return createJSONErrorObject(err)
	}

	return createJSONObject("result", "OK")
}

// readSettingsFileJSON reads the settings file and return the corresponding JSON object
func readSettingsFileJSON() (map[string]interface{}, error) {
	raw, err := ioutil.ReadFile("/etc/config/settings.json")
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
func writeSettingsFileJSON(jsonObject map[string]interface{}) (bool, error) {
	var err error

	// Marshal it back to a string (with ident)
	var jsonString []byte
	jsonString, err = json.MarshalIndent(jsonObject, "", "  ")
	if err != nil {
		return false, err
	}

	err = ioutil.WriteFile("/etc/config/settings.json", jsonString, 0644)
	if err != nil {
		return false, err
	}

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

// Create a JSON object with an error based on the string
func createJSONErrorString(str string) map[string]interface{} {
	return createJSONObject("error", str)
}

// getArrayIndex get an array value by index as a string
func getArrayIndex(array []interface{}, idx string) (interface{}, error) {
	i, err := strconv.Atoi(idx)
	if err != nil {
		return nil, err
	}
	if i >= cap(array) {
		return nil, errors.New("Array index exceeded capacity.")
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
		return nil, errors.New("Array index exceeded capacity.")
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
	} else {
		jsonArray, ok = obj.([]interface{})
		if ok {
			return getArrayIndex(jsonArray, idx)
		} else {
			return nil, errors.New("Unknown type.")
		}
	}
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
	} else {
		jsonArray, ok = obj.([]interface{})
		if ok {
			return setArrayIndex(jsonArray, idx, value)
		} else {
			return nil, errors.New("Unknown type.")
		}
	}
}

// setSettings sets the value attribute specified of the segments path to the specified value
func setSettings(jsonObject interface{}, segments []string, value interface{}) (interface{}, error) {
	var err error

	if len(segments) == 0 {
		// the value is the new jsonObject
		return value, nil
	} else if len(segments) == 1 {
		return setObjectIndex(jsonObject, segments[0], value)
	} else {
		element, newSegments := segments[0], segments[1:]

		mapJsonObject, ok := jsonObject.(map[string]interface{})

		// if this element isnt a map, we cant recurse, so just make it a map
		// this will override the existing value
		if !ok {
			mapJsonObject = make(map[string]interface{})
			jsonObject = mapJsonObject
		}

		// if the next element is null null, create a new map
		if mapJsonObject[element] == nil {
			mapJsonObject[element] = make(map[string]interface{})
		}

		mapJsonObject[element], err = setSettings(mapJsonObject[element], newSegments, value)
		return jsonObject, err
	}
}
