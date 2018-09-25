package restd

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
	"net/http"
	"reflect"
	"strings"
)

func authRequired(engine *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("username")
		if user == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Authorization failed"})
			c.Abort()
		} else {
			c.Next()
		}
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to generate session token"})
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

func validate(username string, password string) bool {
	credentialsJSON := getCredentials(username)
	if credentialsJSON == nil {
		logger.Warn("Failed to find credentials for user %v\n", username)
		return false
	}
	if credentialsJSON["username"] == username && credentialsJSON["passwordCleartext"] == password {
		logger.Info("Successful authentication: %v\n", username)
		return true
	}

	logger.Info("Failed authentication: %v\n", username)
	return false
}
