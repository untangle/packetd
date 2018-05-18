package settings

import (
	"encoding/json"
	"errors"
	"github.com/untangle/packetd/support"
	"io/ioutil"
)

// Settings is the top-level settings object
type Settings struct {
	Version int             `json:"version"`
	Network NetworkSettings `json:"network"`
}

// NetworkSettings is the network settings container object
type NetworkSettings struct {
	Interfaces []InterfaceSettings `json:"interfaces"`
	Options    NetworkOptions      `json:"options"`
}

// NetworkOptions stores global network options
type NetworkOptions struct {
	SendIcmpRedirects bool `json:"sendIcmpRedirects"`
	StrictArpMode     bool `json:"strictArpMode"`
	StpEnabled        bool `json:"stpEnabled"`
	DhcpAuthoritative bool `json:"dhcpAuthoritative"`
}

// InterfaceSettings is the interface settings container object
type InterfaceSettings struct {
	name string
}

// settings stores the current system settings
var settings *Settings

// Startup initializes all settings objects
func Startup() {
	var err error
	settings, err = readSettingsFile()
	if err != nil {
		support.LogMessage("Error reading settings file: %s\n", err.Error())
	}

	if settings == nil {
		support.LogMessage("Initializing new settings...\n")
		settings = new(Settings)

		settings.Version = 1 // version 1 currently

		settings.Network.Options.SendIcmpRedirects = true
		settings.Network.Options.StrictArpMode = true
		settings.Network.Options.StpEnabled = false
		settings.Network.Options.DhcpAuthoritative = true

		_, err := writeSettingsFile(settings)
		if err != nil {
			support.LogMessage("ERROR Initializing new settings: %s\n", err.Error())
		}
	}
}

// GetSettings returns the daemon settings
func GetSettings(segments []string) interface{} {
	var ok bool
	var err error
	var jsonObject map[string]interface{}

	jsonObject, err = readSettingsFileJSON()
	if err != nil {
		return createJSONErrorObject(err)
	}
	for i, value := range segments {
		if value != "" {
			j := jsonObject[value]
			if j == nil {
				return createJSONErrorString("Attribute " + value + " not found in JSON object")
			}
			// if final
			if i == (len(segments) - 1) {
				return j
			}
			jsonObject, ok = j.(map[string]interface{})
			if !ok {
				return createJSONErrorString("Cast error")
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
func SetSettings(segments []string, jsonNewSettings interface{}) interface{} {
	var ok bool
	var err error
	var iterJSONObject map[string]interface{}
	var jsonSettings map[string]interface{}

	jsonSettings, err = readSettingsFileJSON()
	if err != nil {
		return createJSONErrorObject(err)
	}

	iterJSONObject = jsonSettings

	if segments == nil {
		j, ok := jsonNewSettings.(map[string]interface{})
		if ok {
			jsonSettings = j
		} else {
			str, _ := json.Marshal(jsonNewSettings)
			return createJSONErrorString("Invalid global settings object: " + string(str))
		}
	} else {
		for i, value := range segments {
			//if this is the last value, set and break
			if i == len(segments)-1 {
				iterJSONObject[value] = jsonNewSettings
				break
			}

			// otherwise recurse down object
			// 3 cases:
			// if json[foo] does not exist, create a map
			// if json[foo] exists and is a map, recurse
			// if json[foo] exists and is not a map (its some value)
			//    in this case we overwrite with a map, and recurse
			if iterJSONObject[value] == nil {
				newMap := make(map[string]interface{})
				iterJSONObject[value] = newMap
				iterJSONObject = newMap
			} else {
				var j map[string]interface{}
				j, ok = iterJSONObject[value].(map[string]interface{})
				iterJSONObject[value] = make(map[string]interface{})
				if ok {
					iterJSONObject[value] = j
					iterJSONObject = j // for next iteration
				} else {
					newMap := make(map[string]interface{})
					iterJSONObject[value] = newMap // create new map
					iterJSONObject = newMap        // for next iteration
				}
			}
		}
	}

	ok, err = writeSettingsFileJSON(jsonSettings)
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

	ok, err = writeSettingsFileJSON(jsonSettings)
	if err != nil {
		return createJSONErrorObject(err)
	}

	return createJSONObject("result", "OK")
}

// Read the settings file and return the corresponding settings object
func readSettingsFile() (*Settings, error) {
	raw, err := ioutil.ReadFile("/etc/config/settings.json")
	if err != nil {
		return nil, err
	}
	var newSettings = new(Settings)
	err = json.Unmarshal(raw, newSettings)
	if err != nil {
		return nil, err
	}
	return newSettings, nil
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

// Write the specified Settings object to the settings file
func writeSettingsFile(newSettings *Settings) (bool, error) {
	var err error

	if newSettings == nil {
		return false, errors.New("Invalid settings")
	}

	// Marshal it back to a string (with ident)
	var jsonString []byte
	jsonString, err = json.MarshalIndent(newSettings, "", "  ")
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
