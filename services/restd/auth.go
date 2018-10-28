package restd

import (
	"fmt"
	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

func authRequired(engine *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("username")
		if user != nil {
			c.Next()
			return
		}

		ip, port, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err == nil && (ip == "::1" || ip == "127.0.0.1") {
			if isLocalProcessRoot(ip, port) {
				session := sessions.Default(c)
				session.Set("username", "root")
				err := session.Save()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create session"})
				} else {
					c.Next()
					return
				}
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Authorization failed"})
		c.Abort()
	}
}

func authLogin(c *gin.Context) {
	// If this is not a POST, send them to the login page
	// if c.Request.Method != http.MethodPost {
	// 	c.File("/www/admin/login.html")
	// 	return
	// }

	// If this is a POST, but does not have username/password, send them to the login page
	username := c.PostForm("username")
	password := c.PostForm("password")
	if strings.Trim(username, " ") == "" || strings.Trim(password, " ") == "" {
		c.File("/admin/login.html")
		return
	}

	// This is a POST, with a username/password. Try to login
	session := sessions.Default(c)
	if validate(username, password) {
		logger.Info("Login: %s\n", username)
		session.Set("username", username)
		err := session.Save()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create session"})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
		}
	} else {
		logger.Info("Login Failed: %s\n", username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization failed: Invalid username/password"})
	}
}

func authLogout(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("username")
	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session token"})
	} else {
		logger.Info("Logout: %s\n", user)
		session.Delete("username")
		session.Save()
		c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
	}
}

func authStatus(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("username")
	if user == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not logged in"})
	} else {
		username := user.(string)
		credentialsJSON := getCredentials(username)
		for k := range credentialsJSON {
			if strings.HasPrefix(k, "password") {
				delete(credentialsJSON, k)
			}
		}
		c.JSON(http.StatusOK, credentialsJSON)
	}
}

func getCredentials(username string) map[string]interface{} {
	credentialsJSON := settings.GetSettings([]string{"admin", "credentials"})
	if credentialsJSON == nil {
		logger.Warn("Failed to read admin settings: %v\n", credentialsJSON)
		return nil
	}
	credentialsSlice, ok := credentialsJSON.([]interface{})
	if !ok {
		logger.Warn("Invalid type of admin settings: %v %v\n", credentialsJSON, reflect.TypeOf(credentialsJSON))
		return nil
	}

	for _, json := range credentialsSlice {
		cred, ok := json.(map[string]interface{})
		if !ok {
			logger.Warn("Invalid type of admin credentials settings: %v %v\n", json, reflect.TypeOf(json))
			continue
		}
		if cred["username"] == username {
			return cred
		}
	}

	return nil
}

// validate validates the provided username/password against the authorization credentials
// stored in the settings
// returns true if the username/password is valid, false otherwise
func validate(username string, password string) bool {
	credentialsJSON := getCredentials(username)
	if credentialsJSON == nil {
		logger.Warn("Failed to find credentials for user %v\n", username)
		return false
	}
	if credentialsJSON["passwordHashMD5"] == nil {
		logger.Warn("Credentials for %v missing passwordHashMD5\n", username)
		return false
	}
	if credentialsJSON["username"] != username {
		logger.Warn("Assertion failed: getCredentials returned wrong credentials\n")
		return false
	}

	crypt := crypt.MD5.New()
	hash, ok := credentialsJSON["passwordHashMD5"].(string)
	if !ok {
		logger.Warn("Invalid passwordHashMD5 type\n")
	}
	err := crypt.Verify(hash, []byte(password))

	if err == nil {
		logger.Info("Successful authentication: %v\n", username)
		return true
	} else {
		logger.Info("Failed authentication: %v\n", err)
		return false
	}

	logger.Info("Failed authentication: %v\n", username)
	return false
}

// isLocalProcessRoot returns true if the process connecting from the specified ip/port is
// owned by uid 0. It does this by reading the /proc/net/tcp table to determine the owner
// pid and then looking at the uid of any matching pid.
// ip must be "127.0.0.1" or "::1", any other value will return false
// returns true if the local process is found and its uid is 0 (root)
//
// Example: isLocalProcessRoot("127.0.0.1","1234") will return true if the process that
// has the 127.0.0.1:1234 tcp socket open is uid 0 (root).
func isLocalProcessRoot(ip string, port string) bool {
	// ipString is the hex (network order) string of the address
	// that we should find in /proc/net/tcp[6]
	var ipString string
	var procFilename string
	if ip == "127.0.0.1" {
		procFilename = "/proc/net/tcp"
		// 127.0.0.1 in hex (network order)
		ipString = "0100007F"
	} else if ip == "::1" {
		procFilename = "/proc/net/tcp6"
		// ::1 in hex (network order)
		ipString = "00000000000000000000000001000000"
	} else {
		return false
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		logger.Warn("Failed to convert port %s: %v\n", port, err)
		return false
	}

	portString := fmt.Sprintf("%04X", int(portInt))

	// We must read the whole file at once instead of line-by-line
	// to avoid it changing through the read process
	procNetTCPBytes, err := ioutil.ReadFile(procFilename)
	if err != nil {
		logger.Warn("Failed to read /proc/net/tcp: %v\n", err)
		return false
	}

	for _, line := range strings.Split(string(procNetTCPBytes), "\n") {
		words := strings.Fields(line)
		if len(words) < 8 {
			continue
		}

		parts := strings.Split(words[1], ":")
		if len(parts) != 2 {
			continue
		}

		// words[7] is the UID, 0 means uid 0 (root)
		// words[3] is the state, 01 means ESTABLISHED
		if parts[0] == ipString && parts[1] == portString && words[7] == "0" && words[3] == "01" {
			return true
		}
	}

	return false
}
