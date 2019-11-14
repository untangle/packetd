package restd

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt" // MD5 used to verify password
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
)

// CustomJWTPayload stores the custom part of the JWT payload
type CustomJWTPayload struct {
	jwt.Payload
	//IsLoggedIn  bool   `json:"isLoggedIn"`
}

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If alread logged in, continue
		session := sessions.Default(c)
		user := session.Get("username")
		if user != nil {
			c.Next()
			return
		}

		// If the connection is from the local host, check if its authorized
		if checkAuthLocal(c) {
			if !setAuthSession(c, "root", "") {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create 'root' session"})
				c.Abort()
			}

			c.Next()
			return
		}

		// Check if the connection has valid basic http auth credentials
		httpAuth, username, password := checkHTTPAuth(c)
		if httpAuth {
			if !setAuthSession(c, username, password) {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create HTTP auth session"})
				c.Abort()
			}

			c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
			c.Next()
			return
		}

		//Check UN/PW form data
		formAuth, username, password := checkFormAuth(c)

		if formAuth {
			if !setAuthSession(c, username, password) {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create form auth session"})
				c.Abort()
			}
			c.JSON(http.StatusOK, gin.H{"message": "Successfully authenticated user"})
			c.Next()
			return
		}

		//Check the token from cmd/command center
		if checkCommandCenterToken(c) {
			if !setAuthSession(c, "command-center", "") {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create 'command-center' session"})
				c.Abort()
			}

			c.Next()
			return
		}

		// Check if JWT token was specified
		// DISABLED
		// jwtauth, _ := checkJWTToken(c)
		// if jwtauth {
		// 	c.Next()
		// 	return
		// }

		// if the setup wizard is not completed, auth is not required
		if !isSetupWizardCompleted() {
			if !setAuthSession(c, "setup", "") {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create 'setup' session"})
				c.Abort()
			}

			c.Next()
			return
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Authorization failed"})
		c.Abort()
	}
}

// checkJWTToken checks for a token specified in the argument
// if found, it will verify the token and authenticate the user if the JWT is valid
func checkJWTToken(c *gin.Context) (bool, string) {
	now := time.Now()
	hs256 := jwt.NewHMAC(jwt.SHA256, []byte("secret"))
	// FIXME - use RSA
	token := findJWTToken(c)
	// valid hs256 "secret" token
	//token := []byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJNRlciLCJzdWIiOiJ1c2VybmFtZSIsImV4cCI6MTU4Njc0MTAyMywibmJmIjoxNTU1NjM4ODIzLCJpYXQiOjE1NTU2MzcwMjMsImp0aSI6Ik1GVyJ9.ZdfVEqn2TFnkBIr_eIawL-kZ9G3EyE2sekPJ5b0EO_Q")
	// invalid token
	//token := []byte("invalid.jwt.token")
	if token == nil {
		return false, ""
	}

	logger.Info("JWT Token: %v\n", string(token))
	// t, err := createJWT("admin")
	// logger.Info("Wanted : %v\n", string(t))

	raw, err := jwt.Parse(token)
	if err != nil {
		logger.Warn("Invalid token %s\n", err.Error())
		return false, ""
	}
	if err = raw.Verify(hs256); err != nil {
		logger.Warn("Error validating token %s\n", err.Error())
		return false, ""
	}
	var head jwt.Header
	var payload CustomJWTPayload
	if head, err = raw.Decode(&payload); err != nil {
		logger.Warn("Failed to decode token %s\n", err.Error())
		return false, ""
	}
	logger.Info("JWT received: %v %v\n", head.KeyID, head.Algorithm)

	iatValidator := jwt.IssuedAtValidator(now)
	expValidator := jwt.ExpirationTimeValidator(now, true)
	//audValidator := jwt.AudienceValidator(jwt.Audience{"https://example.com"})
	audValidator := func(p *jwt.Payload) error {
		return nil
	}

	if err := payload.Validate(iatValidator, expValidator, audValidator); err != nil {
		switch err {
		case jwt.ErrIatValidation:
			logger.Warn("Failed IssuedAt validation: %s\n", err.Error())
			return false, ""
		case jwt.ErrExpValidation:
			logger.Warn("Failed Expiration validation: %s\n", err.Error())
			return false, ""
		case jwt.ErrAudValidation:
			logger.Warn("Failed Audience validation: %s\n", err.Error())
			return false, ""
		}
	}

	if setAuthSession(c, payload.Payload.Subject, "") {
		logger.Info("JWT accepted: %s\n", payload.Payload.Subject)
		return true, payload.Payload.Subject
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed: Failed to create session"})
	return false, ""
}

// findJWTToken search the arguments and cookie for a JWT
func findJWTToken(c *gin.Context) []byte {
	token := c.Query("jwt")
	if token != "" {
		return []byte(token)
	}
	cookie, _ := c.Cookie("jwt")
	if cookie != "" {
		return []byte(cookie)
	}
	return nil
}

// createJWTToken creates a valid JWT token - used for testing
func createJWTToken(username string) ([]byte, error) {
	now := time.Now()
	hs256 := jwt.NewHMAC(jwt.SHA256, []byte("secret"))
	h := jwt.Header{KeyID: "kid"}
	p := jwt.Payload{
		Issuer:         "MFW",
		Subject:        "username",
		Audience:       nil,
		ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
		NotBefore:      now.Add(30 * time.Minute).Unix(),
		IssuedAt:       now.Unix(),
		JWTID:          "MFW",
	}
	token, err := jwt.Sign(h, p, hs256)
	if err != nil {
		logger.Warn("Failed to sign JWT: %s\n", err.Error())
		return nil, err
	}
	return token, nil
}

// checkHTTPAuth checks the basic http auth & bearer http auth
// returns false if request should continue to next auth technique
// returns true if the auth is valid and the request should be allowed
func checkHTTPAuth(c *gin.Context) (bool, string, string) {
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader == "" {
		// continue, not an error though so don't set an error
		return false, "", ""
	}

	auth := strings.SplitN(c.Request.Header.Get("Authorization"), " ", 2)
	if len(auth) != 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid Authorization Header"})
		return false, "", ""
	}
	if auth[0] != "Basic" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid Authorization Type"})
		return false, "", ""
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[1])
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid Base64 Format in Authorization Header"})
		return false, "", ""
	}

	pair := strings.SplitN(string(decoded), ":", 2)
	if len(pair) != 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid Authorization Header Format"})
		return false, "", ""
	}
	if !validate(pair[0], pair[1]) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Authorization Failed"})
		return false, "", ""
	}

	return true, pair[0], pair[1]
}

// checkAuthLocal checks if the local connecting process is authorized
// returns false if request should continue to next auth technique
// returns true if the auth is valid and the request should be allowed
func checkAuthLocal(c *gin.Context) bool {
	// If the connection is from the local host, check if its authorized
	ip, port, err := net.SplitHostPort(c.Request.RemoteAddr)
	logger.Info("Connection From : %v %v\n", string(ip), port)

	if err == nil && (ip == "::1" || ip == "127.0.0.1") {
		if isLocalProcessRoot(ip, port) {
			return true
		}
	}
	// continue, not an error though so don't set an error
	return false
}

func checkFormAuth(c *gin.Context) (bool, string, string) {
	// If this is not a POST, just return false
	if c.Request.Method != http.MethodPost {
		return false, "", ""
	}

	// If this is a POST, but does not have username/password, send them to the login page
	username := c.PostForm("username")
	password := c.PostForm("password")
	if strings.Trim(username, " ") == "" || strings.Trim(password, " ") == "" {
		return false, "", ""
	}

	// This is a POST, with a username/password. Try to login, set an expiration token for 86400 seconds (24 hours)
	if validate(username, password) {
		return true, username, password
	}

	return false, "", ""
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

// authStatus returns (via a json http reply) the auth status of the current session
func authStatus(c *gin.Context) {
	// if the setup wizard is not completed, auth is not required - return fake user
	if !isSetupWizardCompleted() {
		c.JSON(http.StatusOK, map[string]string{"username": "setup"})
		return
	}

	// if connection is from a local root process
	if checkAuthLocal(c) {
		c.JSON(http.StatusOK, map[string]string{"username": "localroot"})
		return
	}

	// if connection is from command center
	if checkCommandCenterToken(c) {
		c.JSON(http.StatusOK, map[string]string{"username": "command-center"})
		return
	}

	// check JWT
	// jwtauth, jwtuser := checkJWTToken(c)
	// if jwtauth {
	// 	c.JSON(http.StatusOK, map[string]string{"username": jwtuser})
	// 	return
	// }

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
	credentialsJSON, err := settings.GetCurrentSettings([]string{"accounts", "credentials"})
	if credentialsJSON == nil || err != nil {
		logger.Warn("Failed to read accounts settings: %v\n", credentialsJSON)
		return nil
	}
	credentialsSlice, ok := credentialsJSON.([]interface{})
	if !ok {
		logger.Warn("Invalid type of accounts settings: %v %v\n", credentialsJSON, reflect.TypeOf(credentialsJSON))
		return nil
	}

	for _, json := range credentialsSlice {
		cred, ok := json.(map[string]interface{})
		if !ok {
			logger.Warn("Invalid type of accounts credentials settings: %v %v\n", json, reflect.TypeOf(json))
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

// checkCommandCenterToken checks if the untangle auth token is valid
func checkCommandCenterToken(c *gin.Context) bool {
	token := c.Query("token")
	if token == "" {
		session := sessions.Default(c)
		tokenO := session.Get("token")
		if tokenO == nil {
			return false
		}
		token, _ = tokenO.(string)
		if token == "" {
			return false
		}
	}

	uid, err := settings.GetUID()
	if err != nil {
		logger.Warn("Failed to read UID: %s\n", err.Error())
		return false
	}

	postdata := map[string]interface{}{
		"token":      token,
		"resourceId": uid,
	}
	bytesdata, err := json.Marshal(postdata)
	if err != nil {
		logger.Warn("Failed to serialize JSON: %s\n", err.Error())
		return false
	}

	logger.Debug("Verify token: %v\n", token)

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: time.Duration(5 * time.Second)}

	req, err := http.NewRequest("POST", "https://auth.untangle.com/v1/CheckTokenAccess", bytes.NewBuffer(bytesdata))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("AuthRequest", "93BE7735-E9F2-487A-9DD4-9D05B95640F5")

	resp, err := client.Do(req)

	if err != nil {
		logger.Warn("Failed to verify token: %s\n", err.Error())
		return false
	}

	if resp.StatusCode == http.StatusOK {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Warn("Failed to parse body: %s\n", err.Error())
			return false
		}

		logger.Debug("Checking response... %v\n", string(b))

		if string(b) == "true" {

			logger.Debug("Token verification successful \n")
			return true
		}
	}

	logger.Debug("Token verification failed %v\n", resp)

	return false
}

func setAuthSession(c *gin.Context, username string, password string) bool {
	session := sessions.Default(c)
	session.Set("username", username)

	if strings.Trim(password, " ") != "" {
		session.Set("password", password)
	}

	session.Options(sessions.Options{Path: "/", MaxAge: 86400})

	err := session.Save()
	if err == nil {
		return true
	}

	return false
}
