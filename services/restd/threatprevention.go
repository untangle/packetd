package restd

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/webroot"
)

// threatpreventionGetInfo gets info on a particular host or IP.
func threatpreventionGetInfo(c *gin.Context) {
	logger.Debug("threatpreventionGetInfo() \n")
	
	host := c.Param("host")

	result, err := webroot.GetInfo(host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.Header("Content-Type", "application/json")
	c.String(http.StatusOK, string(result))
	return
}