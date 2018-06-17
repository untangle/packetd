package reports

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3" // blank import required for runtime binding
	"github.com/untangle/packetd/services/support"
	"sync/atomic"
	"time"
)

// An arbitrary event
type Event struct {
	Name            string
	Table           string
	SqlOp           int // 1 - INSERT // 2 - UPDATE
	Columns         map[string]interface{}
	ModifiedColumns map[string]interface{}
}

// Query holds the results of a database query operation
type Query struct {
	ID   uint64
	Rows *sql.Rows
}

var db *sql.DB
var queries = make(map[uint64]*Query)
var queryID uint64
var appname = "reports"
var eventQueue = make(chan Event)

// Initialize creates a connection to the database
func Startup() {
	var err error
	db, err = sql.Open("sqlite3", "/tmp/reports.db")

	if err != nil {
		support.LogMessage(support.LogErr, appname, "Failed to open database: %s\n", err.Error())
	}

	go createTables()
}

// Shutdown reports
func Shutdown() {
	db.Close()
}

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

// GetData returns the data for the provided QueryID
func GetData(queryID uint64) (string, error) {
	q := queries[queryID]
	if q == nil {
		support.LogMessage(support.LogWarn, appname, "Query not found: %d\n", queryID)
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

// Create an Event
func CreateEvent(name string, table string, sqlOp int, columns map[string]interface{}, modifiedColumns map[string]interface{}) Event {
	event := Event{Name: name, Table: table, SqlOp: sqlOp, Columns: columns, ModifiedColumns: modifiedColumns}
	return event
}

// Log an Event
func LogEvent(event Event) error {
	eventQueue <- event
	return nil
}

func eventLogger() {
	var summary string
	for {
		event := <-eventQueue
		summary = event.Name + "|" + event.Table + "|"
		if event.SqlOp == 1 {
			str, err := json.Marshal(event.Columns)
			if err == nil {
				summary = summary + "INSERT: " + string(str)
			}
		}
		if event.SqlOp == 2 {
			str, err := json.Marshal(event.ModifiedColumns)
			if err == nil {
				summary = summary + "UPDATE: " + string(str)
			}
		}
		support.LogMessage(support.LogInfo, appname, "Log Event: %s\n", summary)
	}
}

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

func cleanupQuery(query *Query) {
	support.LogMessage(support.LogDebug, appname, "cleanupQuery(%d) launched\n", query.ID)
	time.Sleep(30 * time.Second)
	delete(queries, query.ID)
	if query.Rows != nil {
		query.Rows.Close()
	}
	support.LogMessage(support.LogDebug, appname, "cleanupQuery(%d) finished\n", query.ID)
}

func createTables() {
	var err error

	_, err = db.Exec(
		`CREATE TABLE sessions (
                     session_id int8 PRIMARY KEY NOT NULL,
                     time_stamp timestamp NOT NULL,
                     end_time timestamp,
                     ip_protocol int2,
                     hostname text,
                     username text,
                     client_intf int2,
                     server_intf int2,
                     local_addr inet,
                     remote_addr inet,
                     client_addr inet,
                     server_addr inet,
                     client_port int4,
                     server_port int4,
                     client_addr_new inet,
                     server_addr_new inet,
                     server_port_new int4,
                     client_port_new int4,
                     client_country text,
                     client_latitude real,
                     client_longitude real,
                     server_country text,
                     server_latitude real,
                     server_longitude real,
                     c2s_bytes int8 default 0,
                     s2c_bytes int8 default 0)`)

	if err != nil {
		support.LogMessage(support.LogErr, appname, "Failed to create table: %s\n", err.Error())
	}

	//test REMOVE ME
	_, err = db.Exec("INSERT INTO sessions (time_stamp, session_id) VALUES (DATETIME('now'),1)")
	if err != nil {
		support.LogMessage(support.LogErr, appname, "Failed to insert: %s\n", err.Error())
	}

	eventLogger()
}
