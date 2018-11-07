package reports

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3" // blank import required for runtime binding
	"github.com/untangle/packetd/services/logger"
	"strconv"
	"sync/atomic"
	"time"
)

// Event stores an arbitrary event
type Event struct {
	// Name - A human readable name for this event. (ie "session_new" is a new session event)
	Name string
	// Table - the DB table that this event modifies (or nil)
	Table string
	// SQLOp - the SQL operation needed to serialize the event to the DB
	// 1 - INSERT // 2 - UPDATE
	SQLOp int
	// The columns in the DB this inserts for INSERTS or qualifies if matches for UPDATES
	Columns map[string]interface{}
	// The columns to modify for UPDATE events
	ModifiedColumns map[string]interface{}
}

// Query holds the results of a database query operation
type Query struct {
	ID   uint64
	Rows *sql.Rows
}

// QueryCategoriesOptions stores the query options for CATEGORY type reports
type QueryCategoriesOptions struct {
	CategoriesGroupColumn         string `json:"categoriesGroupColumn"`
	CategoriesAggregationFunction string `json:"categoriesAggregationFunction"`
	CategoriesAggregationValue    string `json:"categoriesAggregationValue"`
	CategoriesLimit               int    `json:"categoriesLimit"`
	CategoriesOrderByColumn       int    `json:"categoriesOrderByColumn"`
	CategoriesOrderAsc            bool   `json:"categoriesOrderAsc"`
}

// QueryTextOptions stores the query options for TEXT type reports
type QueryTextOptions struct {
	TextColumns []string `json:"textColumns"`
}

// QuerySeriesOptions stores the query options for SERIES type reports
type QuerySeriesOptions struct {
	SeriesColumns             []string `json:"seriesColumns"`
	SeriesTimeIntervalSeconds int      `json:"seriesTimeIntervalSeconds"`
}

// ReportEntry is a report entry as defined in the JSON schema
type ReportEntry struct {
	UniqueID        string                 `json:"uniqueId"`
	Name            string                 `json:"name"`
	Category        string                 `json:"category"`
	Description     string                 `json:"description"`
	DisplayOrder    int                    `json:"displayOrder"`
	ReadOnly        bool                   `json:"readOnly"`
	Type            string                 `json:"type"`
	Table           string                 `json:"table"`
	QueryCategories QueryCategoriesOptions `json:"queryCategories"`
	QueryText       QueryTextOptions       `json:"queryText"`
	QuerySeries     QuerySeriesOptions     `json:"querySeries"`
}

var db *sql.DB
var queries = make(map[uint64]*Query)
var queryID uint64
var eventQueue = make(chan Event, 1000)

// Startup starts the reports service
func Startup() {
	var err error
	db, err = sql.Open("sqlite3", "/tmp/reports.db")

	if err != nil {
		logger.Err("Failed to open database: %s\n", err.Error())
	}

	go func() {
		createTables()
		eventLogger()
	}()
}

// Shutdown stops the reports service
func Shutdown() {
	db.Close()
}

// CreateQuery submits a database query and returns the results
func CreateQuery(reportEntryStr string, startTimeStr string, endTimeStr string) (*Query, error) {
	reportEntry := &ReportEntry{}

	var err error
	var startTimeEpoch int64
	var endTimeEpoch int64

	if startTimeStr == "" {
		startTimeEpoch = time.Now().Add(-1 * time.Duration(24) * time.Hour).Unix()
	} else {
		startTimeEpoch, err = strconv.ParseInt(startTimeStr, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	startTime := time.Unix(startTimeEpoch, 0)

	if endTimeStr == "" {
		endTimeEpoch = time.Now().Add(time.Duration(1) * time.Minute).Unix()
	} else {
		endTimeEpoch, err = strconv.ParseInt(endTimeStr, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	endTime := time.Unix(endTimeEpoch, 0)

	err = json.Unmarshal([]byte(reportEntryStr), reportEntry)
	if err != nil {
		logger.Err("json.Unmarshal error: %s\n", err)
		return nil, err
	}
	logger.Debug("ReportEntry: %v\n", reportEntry)

	var rows *sql.Rows
	var sqlStr string

	sqlStr, err = makeSQLString(reportEntry, startTime, endTime) // FIXME add conditions
	if err != nil {
		return nil, err
	}

	logger.Info("SQL: %v\n", sqlStr)
	rows, err = db.Query(sqlStr)
	if err != nil {
		logger.Err("db.Query error: %s\n", err)
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
		logger.Warn("Query not found: %d\n", queryID)
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

// CreateEvent creates an Event
func CreateEvent(name string, table string, sqlOp int, columns map[string]interface{}, modifiedColumns map[string]interface{}) Event {
	event := Event{Name: name, Table: table, SQLOp: sqlOp, Columns: columns, ModifiedColumns: modifiedColumns}
	return event
}

// LogEvent adds an event to the eventQueue for later logging
func LogEvent(event Event) error {
	eventQueue <- event
	return nil
}

// eventLogger readns from the eventQueue and logs the events to sqlite
func eventLogger() {
	var summary string
	for {
		event := <-eventQueue
		summary = event.Name + "|" + event.Table + "|"
		if event.SQLOp == 1 {
			str, err := json.Marshal(event.Columns)
			if err == nil {
				summary = summary + "INSERT: " + string(str)
			}
		}
		if event.SQLOp == 2 {
			str, err := json.Marshal(event.ModifiedColumns)
			if err == nil {
				summary = summary + "UPDATE: " + string(str)
			} else {
				logger.Warn("ERROR: %s\n", err.Error())
			}
		}
		logger.Debug("Log Event: %s %v\n", summary, event.SQLOp)

		if event.SQLOp == 1 {
			logInsertEvent(event)
		}
		if event.SQLOp == 2 {
			logUpdateEvent(event)
		}
	}
}

func logInsertEvent(event Event) {
	var sqlStr = "INSERT INTO " + event.Table + "("
	var valueStr = "("

	var first = true
	var values []interface{}
	for k, v := range event.Columns {
		if !first {
			sqlStr += ","
			valueStr += ","
		}
		sqlStr += k
		valueStr += "?"
		first = false
		timestamp, ok := v.(time.Time)
		if ok {
			// Special handle time.Time
			// We want to log these as milliseconds since epoch
			values = append(values, timestamp.UnixNano()/1e6)
		} else {
			values = append(values, v)
		}
	}
	sqlStr += ")"
	valueStr += ")"
	sqlStr += " VALUES " + valueStr

	logger.Debug("SQL: %s\n", sqlStr)
	stmt, err := db.Prepare(sqlStr)
	if err != nil {
		logger.Warn("Failed to prepare statement: %s %s\n", err.Error(), sqlStr)
		return
	}
	_, err = stmt.Exec(values...)
	if err != nil {
		logger.Warn("Failed to exec statement: %s %s\n", err.Error(), sqlStr)
		return
	}

	err = stmt.Close()
	if err != nil {
		logger.Warn("Failed to close statement: %s %s\n", err.Error(), sqlStr)
	}
}

func logUpdateEvent(event Event) {
	var sqlStr = "UPDATE " + event.Table + " SET"

	var first = true
	var values []interface{}
	for k, v := range event.ModifiedColumns {
		if !first {
			sqlStr += ","
		}

		sqlStr += " " + k + " = ?"
		values = append(values, v)
		first = false
	}

	sqlStr += " WHERE "
	first = true
	for k, v := range event.Columns {
		if !first {
			sqlStr += " AND "
		}

		sqlStr += " " + k + " = ?"
		values = append(values, v)
		first = false
	}

	logger.Debug("SQL: %s\n", sqlStr)
	stmt, err := db.Prepare(sqlStr)
	if err != nil {
		logger.Warn("Failed to prepare statement: %s %s\n", err.Error(), sqlStr)
		return
	}
	_, err = stmt.Exec(values...)
	if err != nil {
		logger.Warn("Failed to exec statement: %s %s\n", err.Error(), sqlStr)
		return
	}

	err = stmt.Close()
	if err != nil {
		logger.Warn("Failed to close statement: %s %s\n", err.Error(), sqlStr)
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
	logger.Debug("cleanupQuery(%d) launched\n", query.ID)
	time.Sleep(30 * time.Second)
	delete(queries, query.ID)
	if query.Rows != nil {
		query.Rows.Close()
	}
	logger.Debug("cleanupQuery(%d) finished\n", query.ID)
}

func createTables() {
	var err error

	_, err = db.Exec(
		`CREATE TABLE IF NOT EXISTS sessions (
                     session_id int8 PRIMARY KEY NOT NULL,
                     time_stamp bigint NOT NULL,
                     end_time bigint,
                     ip_protocol int,
                     hostname text,
                     username text,
                     client_interface int,
                     server_interface int,
                     local_address  inet,
                     remote_address inet,
                     client_address inet,
                     server_address inet,
                     client_port int2,
                     server_port int2,
                     client_address_new inet,
                     server_address_new inet,
                     server_port_new int2,
                     client_port_new int2,
                     client_country text,
                     client_latitude real,
                     client_longitude real,
                     server_country text,
                     server_latitude real,
                     server_longitude real,
                     c2s_bytes int8 default 0,
                     s2c_bytes int8 default 0,
                     application_id text,
                     application_name text,
                     application_protochain text,
                     application_category text,
                     application_blocked boolean,
                     application_flagged boolean,
                     application_confidence integer,
                     application_detail text,
                     dns_prediction text,
                     dns_prediction_category text)`)

	// FIXME add cert info
	// FIXME add SNI
	// FIXME add domain_prediction (SNI + dns_prediction + cert_prediction)
	// FIXME add domain_category
	// FIXME add web_domain (for HTTP host header)

	if err != nil {
		logger.Err("Failed to create table: %s\n", err.Error())
	}
}
