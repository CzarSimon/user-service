package httputil

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// NewRouter creates a default router.
func NewRouter(name, version string) *gin.Engine {
	r := gin.New()
	r.Use(
		Logger(),
		gin.Recovery(),
		ServerInfo(name, version),
		RequestID(),
		HandleErrors())

	return r
}

// SendOK sends an ok status and message to the client.
func SendOK(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

// ParseQueryValue parses a query value from request.
func ParseQueryValue(c *gin.Context, key string) (string, error) {
	value, ok := c.GetQuery(key)
	if !ok {
		errMsg := fmt.Sprintf("No value found for param: %s", key)
		return "", NewError(errMsg, http.StatusBadRequest)
	}
	return value, nil
}

// ParseQueryValues parses query values from a request.
func ParseQueryValues(c *gin.Context, key string) ([]string, error) {
	values, ok := c.GetQueryArray(key)
	if !ok {
		errMsg := fmt.Sprintf("No value found for param: %s", key)
		return nil, NewError(errMsg, http.StatusBadRequest)
	}
	return values, nil
}
