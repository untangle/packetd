package reports

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3" // blank import required for runtime binding
	"github.com/untangle/packetd/support"
	"log"
	"sync/atomic"
	"time"
)

var db *sql.DB
var queries = make(map[uint64]*Query)
var queryID uint64
var appname = "reports"

//-----------------------------------------------------------------------------

// Query holds the results of a database query operation
type Query struct {
	ID   uint64
	Rows *sql.Rows
}

//-----------------------------------------------------------------------------

// ConnectDb creates a connection to the database
func ConnectDb() {
	var err error
	db, err = sql.Open("sqlite3", "/tmp/reports.db")

	if err != nil {
		log.Fatal(err)
	}
}

//-----------------------------------------------------------------------------

// CreateQuery submits a database query and returns the results
func CreateQuery(reportEntry string) (*Query, error) {
	rows, err := db.Query("SELECT * FROM sessions LIMIT 5")
	if err != nil {
		support.LogMessage(support.LogErr, appname, "db.Query error: %s\n", err)
		return nil, err
	}
	q := new(Query)
	q.ID = atomic.AddUint64(&queryID, 1)
	q.Rows = rows

	queries[q.ID] = q
	go cleanupQuery(q)
	return q, nil
}

//-----------------------------------------------------------------------------

// GetData returns the data for the provided QueryID
func GetData(queryID uint64) (string, error) {
	q := queries[queryID]
	if q == nil {
		support.LogMessage(support.LogWarning, appname, "Query not found: %d\n", queryID)
		return "", errors.New("Query ID not found")
	}
	result, err := getRows(q.Rows, 1000)
	if err != nil {
		return "", err
	}
	jsonData, err := json.Marshal(result)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

//-----------------------------------------------------------------------------

func getRows(rows *sql.Rows, limit int) ([]map[string]interface{}, error) {
	if rows == nil {
		return nil, errors.New("Invalid argument")
	}
	if limit < 1 {
		return nil, errors.New("Invalid limit")
	}

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	columnCount := len(columns)

	tableData := make([]map[string]interface{}, 0)
	values := make([]interface{}, columnCount)
	valuePtrs := make([]interface{}, columnCount)

	for i := 0; rows.Next() && i < limit; i++ {
		for i := 0; i < columnCount; i++ {
			valuePtrs[i] = &values[i]
		}
		rows.Scan(valuePtrs...)
		entry := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			entry[col] = v
		}
		tableData = append(tableData, entry)
	}

	return tableData, nil
}

//-----------------------------------------------------------------------------

func cleanupQuery(query *Query) {
	support.LogMessage(support.LogDebug, appname, "cleanupQuery(%d) launched\n", query.ID)
	time.Sleep(30 * time.Second)
	delete(queries, query.ID)
	if query.Rows != nil {
		query.Rows.Close()
	}
	support.LogMessage(support.LogDebug, appname, "cleanupQuery(%d) finished\n", query.ID)
}

//-----------------------------------------------------------------------------
