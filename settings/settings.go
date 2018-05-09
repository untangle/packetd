package settings

import (
	"encoding/json"
	"errors"
	"io/ioutil"
)

func GetSettings(segments []string) interface{} {
	var ok bool
	var err error
	var jsonObject map[string]interface{}

	jsonObject, err = readSettingsFile()
	if err != nil {
		return createJsonErrorObject(err)
	}
	for i, value := range segments {
		if value != "" {
			j := jsonObject[value]
			if j == nil {
				return createJsonErrorString("Attribute " + value + " not found in JSON object")
			}
			// if final
			if i == (len(segments) - 1) {
				return j
			}
			jsonObject, ok = j.(map[string]interface{})
			if !ok {
				return createJsonErrorString("Cast error")
			}
		}
	}

	return jsonObject
}

func SetSettingsParse(segments []string, byteSlice []byte) interface{} {
	var err error
	var bodyJsonObject interface{}

	err = json.Unmarshal(byteSlice, &bodyJsonObject)
	if err != nil {
		return createJsonErrorObject(err)
	}

	return SetSettings(segments, bodyJsonObject)
}

func SetSettings(segments []string, jsonNewSettings interface{}) interface{} {
	var ok bool
	var err error
	var iterJsonObject map[string]interface{}
	var jsonSettings map[string]interface{}

	jsonSettings, err = readSettingsFile()
	if err != nil {
		return createJsonErrorObject(err)
	}

	iterJsonObject = jsonSettings

	if segments == nil {
		j, ok := jsonNewSettings.(map[string]interface{})
		if ok {
			jsonSettings = j
		} else {
			str, _ := json.Marshal(jsonNewSettings)
			return createJsonErrorString("Invalid global settings object: " + string(str))
		}
	} else {
		for i, value := range segments {
			//if this is the last value, set and break
			if i == len(segments)-1 {
				iterJsonObject[value] = jsonNewSettings
				break
			}

			// otherwise recurse down object
			// 3 cases:
			// if json[foo] does not exist, create a map
			// if json[foo] exists and is a map, recurse
			// if json[foo] exists and is not a map (its some value)
			//    in this case we overwrite with a map, and recurse
			if iterJsonObject[value] == nil {
				newMap := make(map[string]interface{})
				iterJsonObject[value] = newMap
				iterJsonObject = newMap
			} else {
				var j map[string]interface{}
				j, ok = iterJsonObject[value].(map[string]interface{})
				iterJsonObject[value] = make(map[string]interface{})
				if ok {
					iterJsonObject[value] = j
					iterJsonObject = j // for next iteration
				} else {
					newMap := make(map[string]interface{})
					iterJsonObject[value] = newMap // create new map
					iterJsonObject = newMap        // for next iteration
				}
			}
		}
	}

	ok, err = writeSettingsFile(jsonSettings)
	if err != nil {
		return createJsonErrorObject(err)
	} else {
		return createJsonObject("result", "OK")
	}
}

func TrimSettings(segments []string) interface{} {
	var ok bool
	var err error
	var iterJsonObject map[string]interface{}
	var jsonSettings map[string]interface{}

	if segments == nil {
		return createJsonErrorString("Invalid trim settings path")
	}

	jsonSettings, err = readSettingsFile()
	if err != nil {
		return createJsonErrorObject(err)
	}

	iterJsonObject = jsonSettings

	for i, value := range segments {
		//if this is the last value, set and break
		if i == len(segments)-1 {
			delete(iterJsonObject, value)
			break
		}

		// otherwise recurse down object
		// 3 cases:
		// if json[foo] does not exist, nothing to delete
		// if json[foo] exists and is a map, recurse
		// if json[foo] exists and is not a map (its some value)
		//    in this case we throw an error
		if iterJsonObject[value] == nil {
			// path does not exists - nothing to delete, just quit
			break
		} else {
			var j map[string]interface{}
			j, ok = iterJsonObject[value].(map[string]interface{})
			iterJsonObject[value] = make(map[string]interface{})
			if ok {
				iterJsonObject[value] = j
				iterJsonObject = j // for next iteration
			} else {
				return createJsonErrorString("Non-dict found in path: " + string(value))
			}
		}
	}

	ok, err = writeSettingsFile(jsonSettings)
	if err != nil {
		return createJsonErrorObject(err)
	} else {
		return createJsonObject("result", "OK")
	}
}

func readSettingsFile() (map[string]interface{}, error) {
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
	} else {
		return nil, errors.New("Invalid settings file format")
	}
}

func writeSettingsFile(jsonObject map[string]interface{}) (bool, error) {
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

func createJsonObject(key string, value string) map[string]interface{} {
	return map[string]interface{}{key: value}
}

func createJsonErrorObject(e error) map[string]interface{} {
	return createJsonObject("error", e.Error())
}

func createJsonErrorString(str string) map[string]interface{} {
	return createJsonObject("error", str)
}
