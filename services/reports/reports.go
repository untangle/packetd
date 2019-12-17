package reports

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mattn/go-sqlite3"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/packetd/services/logger"
	"github.com/untangle/packetd/services/settings"
)

// Event stores an arbitrary event
type Event struct {
	// Name - A human readable name for this event. (ie "session_new" is a new session event)
	Name string `json:"name"`
	// Table - the DB table that this event modifies (or nil)
	Table string `json:"table"`
	// SQLOp - the SQL operation needed to serialize the event to the DB
	// 1 - INSERT // 2 - UPDATE
	SQLOp int `json:"sqlOp"`
	// The columns in the DB this inserts for INSERTS or qualifies if matches for UPDATES
	Columns map[string]interface{} `json:"columns"`
	// The columns to modify for UPDATE events
	ModifiedColumns map[string]interface{} `json:"modifiedColumns"`
}

// Query holds the results of a database query operation
type Query struct {
	ID   uint64
	Rows *sql.Rows
}

// QueryCategoriesOptions stores the query options for CATEGORY type reports
type QueryCategoriesOptions struct {
	GroupColumn         string `json:"groupColumn"`
	AggregationFunction string `json:"aggregationFunction"`
	AggregationValue    string `json:"aggregationValue"`
	Limit               int    `json:"limit"`
	OrderByColumn       int    `json:"orderByColumn"`
	OrderAsc            bool   `json:"orderAsc"`
}

// QueryTextOptions stores the query options for TEXT type reports
type QueryTextOptions struct {
	Columns []string `json:"columns"`
}

// QuerySeriesOptions stores the query options for SERIES type reports
type QuerySeriesOptions struct {
	Columns             []string `json:"columns"`
	TimeIntervalSeconds int      `json:"timeIntervalSeconds"`
}

// QueryEventsOptions stores the query options for EVENTS type reports
type QueryEventsOptions struct {
	OrderByColumn string `json:"orderByColumn"`
	OrderAsc      bool   `json:"orderAsc"`
	Limit         int    `json:"limit"`
}

// ReportCondition holds a SQL reporting condition (ie client = 1.2.3.4)
type ReportCondition struct {
	Column   string      `json:"column"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// ReportColumnDisambiguation remove and ambigious column names (used for joins)
type ReportColumnDisambiguation struct {
	ColumnName    string `json:"columnName"`
	NewColumnName string `json:"newColumnName"`
}

// ReportEntry is a report entry as defined in the JSON schema
type ReportEntry struct {
	UniqueID             string                       `json:"uniqueId"`
	Name                 string                       `json:"name"`
	Category             string                       `json:"category"`
	Description          string                       `json:"description"`
	DisplayOrder         int                          `json:"displayOrder"`
	ReadOnly             bool                         `json:"readOnly"`
	Type                 string                       `json:"type"`
	Table                string                       `json:"table"`
	Conditions           []ReportCondition            `json:"conditions"`
	ColumnDisambiguation []ReportColumnDisambiguation `json:"columnDisambiguation"`
	UserConditions       []ReportCondition            `json:"userConditions"`
	QueryCategories      QueryCategoriesOptions       `json:"queryCategories"`
	QueryText            QueryTextOptions             `json:"queryText"`
	QuerySeries          QuerySeriesOptions           `json:"querySeries"`
	QueryEvents          QueryEventsOptions           `json:"queryEvents"`
}

var dbMain *sql.DB
var queriesMap = make(map[uint64]*Query)
var queriesLock sync.RWMutex
var queryID uint64
var eventQueue = make(chan Event, 10000)
var cloudQueue = make(chan Event, 1000)

// The filename and path for the sqlite database file. We split these up to make
// it easy for the file size limitation logic to get the total size of the target
// directory so we can calculate our limit as a percentage of the total size.
const dbFILENAME = "reports.db"
const dbFILEPATH = "/tmp"
const oneMEGABYTE = 1024 * 1024

// dbDISKPERCENTAGE is used to calculate the maximum database file size
const dbDISKPERCENTAGE = 0.40

// dbFREEMINIMUM sets the minimum amount of free page space below which
// we will start deleting older rows from the database tables once
// the database file grows to the maximum calculated size
const dbFREEMINIMUM int64 = 32768

// dbSizeLimit is the calculated maximum size for the database file
var dbSizeLimit int64

// Startup starts the reports service
func Startup() {
	var stat syscall.Statfs_t
	var dsn string
	var err error
	// eventBatchSize is the size of event batches for batching inserts/updates from the event queue
	var eventBatchSize int

	// get the file system stats for the path where the database will be stored
	syscall.Statfs(dbFILEPATH, &stat)

	// set the database size limit to 60 percent of the total space available
	dbSizeLimit = int64(float64(stat.Bsize) * float64(stat.Blocks) * dbDISKPERCENTAGE)

	// set the event log processing batch size
	eventBatchSize = 1000

	// register a custom driver with a connect hook where we can set our pragma's for
	// all connections that get created. This is needed because pragma's are applied
	// per connection. Since the sql package does connection pooling and management,
	// the hook lets us set the right pragma's for each and every connection.
	sql.Register("sqlite3_custom", &sqlite3.SQLiteDriver{ConnectHook: customHook})

	dbVersion, _, _ := sqlite3.Version()
	dsn = fmt.Sprintf("file:%s/%s?mode=rwc", dbFILEPATH, dbFILENAME)
	dbMain, err = sql.Open("sqlite3_custom", dsn)

	if err != nil {
		logger.Err("Failed to open database: %s\n", err.Error())
	} else {
		logger.Info("SQLite3 Database Version:%s  File:%s/%s  Limit:%d MB\n", dbVersion, dbFILEPATH, dbFILENAME, dbSizeLimit/oneMEGABYTE)
	}

	dbMain.SetMaxOpenConns(1)
	dbMain.SetMaxIdleConns(2)

	createTables()

	go eventLogger(eventBatchSize)
	go dbCleaner()

	if !kernel.FlagNoCloud {
		go cloudSender()
	}
}

// Shutdown stops the reports service
func Shutdown() {
	dbMain.Close()
}

// customHook is used set the parameters we need for every database connection
func customHook(conn *sqlite3.SQLiteConn) error {
	// turn off sync to disk after every transaction for improved performance
	if _, err := conn.Exec("PRAGMA synchronous = OFF", nil); err != nil {
		logger.Warn("Error setting synchronous: %v\n", err)
	}

	// store the rollback journal in memory for improved performance
	if _, err := conn.Exec("PRAGMA journal_mode = MEMORY", nil); err != nil {
		logger.Warn("Error setting journal_mode: %v\n", err)
	}

	// setting a busy timeout will allow the driver to retry for the specified
	// number of milliseconds instead of immediately returning SQLITE_BUSY when
	// a table is locked
	if _, err := conn.Exec("PRAGMA busy_timeout = 10000", nil); err != nil {
		logger.Warn("Error setting busy_timeout: %v\n", err)
	}

	// enable auto vaccuum = FULL
	if _, err := conn.Exec("PRAGMA auto_vacuum = FULL", nil); err != nil {
		logger.Warn("Error setting auto_vacuum: %v\n", err)
	}
	return nil
}

func unmarshall(reportEntryStr string, reportEntry *ReportEntry) error {
	decoder := json.NewDecoder(strings.NewReader(reportEntryStr))
	decoder.UseNumber()
	err := decoder.Decode(reportEntry)
	// err := json.Unmarshal(reportEntryBytes, reportEntry)
	if err != nil {
		return err
	}
	return nil
}

// CreateQuery submits a database query and returns the results
func CreateQuery(reportEntryStr string) (*Query, error) {
	var err error
	reportEntry := &ReportEntry{}

	err = unmarshall(reportEntryStr, reportEntry)
	if err != nil {
		logger.Err("json.Unmarshal error: %s\n", err)
		return nil, err
	}
	logger.Debug("ReportEntry: %v\n", reportEntry)

	mergeConditions(reportEntry)
	err = addOrUpdateTimestampConditions(reportEntry)
	if err != nil {
		logger.Err("Timestamp condition error: %s\n", err)
		return nil, err
	}

	var rows *sql.Rows
	var sqlStr string

	sqlStr, err = makeSQLString(reportEntry)
	if err != nil {
		logger.Warn("Failed to make SQL: %v\n", err)
		return nil, err
	}
	values := conditionValues(reportEntry.Conditions)

	logger.Debug("SQL: %v %v\n", sqlStr, values)
	rows, err = dbMain.Query(sqlStr, values...)
	if err != nil {
		logger.Err("dbMain.Query error: %s\n", err)
		return nil, err
	}

	q := new(Query)
	q.ID = atomic.AddUint64(&queryID, 1)
	q.Rows = rows

	queriesLock.Lock()
	queriesMap[q.ID] = q
	queriesLock.Unlock()
	go func() {
		time.Sleep(30 * time.Second)
		cleanupQuery(q)
	}()
	return q, nil
}

// GetData returns the data for the provided QueryID
func GetData(queryID uint64) (string, error) {
	queriesLock.RLock()
	q := queriesMap[queryID]
	queriesLock.RUnlock()
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

// CloseQuery closes the query now
func CloseQuery(queryID uint64) (string, error) {
	queriesLock.RLock()
	q := queriesMap[queryID]
	queriesLock.RUnlock()
	if q == nil {
		logger.Warn("Query not found: %d\n", queryID)
		return "", errors.New("Query ID not found")
	}
	cleanupQuery(q)
	return "Success", nil
}

// CreateEvent creates an Event
func CreateEvent(name string, table string, sqlOp int, columns map[string]interface{}, modifiedColumns map[string]interface{}) Event {
	event := Event{Name: name, Table: table, SQLOp: sqlOp, Columns: columns, ModifiedColumns: modifiedColumns}
	return event
}

// LogEvent adds an event to the eventQueue for later logging
func LogEvent(event Event) error {
	select {
	case eventQueue <- event:
	default:
		// log the message with the OC verb passing the counter name and the repeat message limit as the first two arguments
		logger.Warn("%OC|Event queue at capacity[%d]. Dropping event: %v\n", "reports_event_queue_full", 100, cap(eventQueue), event)
		return errors.New("Event Queue at Capacity")
	}
	return nil
}

// eventLogger readns from the eventQueue and logs the events to sqlite
// this processes the items in {eventBatchSize} batches, or after 60 seconds of being unread in the channel
// items that are not in the current batch will remain
// unread on the channel until the current batch is committed into the database
// param eventBatchSize (int) - the size of the batch to commit into the database
func eventLogger(eventBatchSize int) {
	var eventBatch []Event
	var lastInsert time.Time
	waitTime := 60.0

	for {
		// read data out of the eventQueue into the eventBatch
		eventBatch = append(eventBatch, <-eventQueue)

		// when the batch is larger than the configured batch insert size OR we haven't inserted anything in one minute, we need to insert some stuff
		batchCount := len(eventBatch)
		if batchCount >= eventBatchSize || time.Since(lastInsert).Seconds() > waitTime {
			logger.Debug("%v Items ready for batch, starting transaction at %v...\n", batchCount, time.Now())

			tx, err := dbMain.Begin()
			if err != nil {
				logger.Warn("Failed to begin transaction: %s\n", err.Error())
			}

			//iterate events in the batch and send them into the db transaction
			for _, event := range eventBatch {
				eventToTransaction(event, tx)
			}

			// end transaction
			err = tx.Commit()
			if err != nil {
				tx.Rollback()
				logger.Warn("Failed to commit transaction: %s\n", err.Error())
			}

			logger.Debug("Transaction completed, %v items processed at %v .\n", batchCount, lastInsert)
			eventBatch = nil
			lastInsert = time.Now()
		}
	}

}

// eventToTransaction converts the Event object into a Sql Transaction and appends it into the current transaction context
// param event (Event) - the event to process
// param tx (*sql.Tx) - the transaction context
func eventToTransaction(event Event, tx *sql.Tx) {
	var sqlStr string
	var values []interface{}
	var first = true

	// sqlOP 1 is an INSERT
	if event.SQLOp == 1 {
		sqlStr = "INSERT INTO " + event.Table + "("
		var valueStr = "("
		for k, v := range event.Columns {
			if !first {
				sqlStr += ","
				valueStr += ","
			}
			sqlStr += k
			valueStr += "?"
			first = false
			values = append(values, prepareEventValues(v))
		}
		sqlStr += ")"
		valueStr += ")"
		sqlStr += " VALUES " + valueStr
	}

	// sqlOP 2 is an UPDATE
	if event.SQLOp == 2 {
		sqlStr = "UPDATE " + event.Table + " SET"
		for k, v := range event.ModifiedColumns {
			if !first {
				sqlStr += ","
			}

			sqlStr += " " + k + " = ?"
			values = append(values, prepareEventValues(v))
			first = false
		}

		sqlStr += " WHERE "
		first = true
		for k, v := range event.Columns {
			if !first {
				sqlStr += " AND "
			}

			sqlStr += " " + k + " = ?"
			values = append(values, prepareEventValues(v))
			first = false
		}
	}

	res, err := tx.Exec(sqlStr, values...)
	if err != nil {
		logger.Warn("Failed to execute transaction: %s %s\n", err.Error(), sqlStr)
		return
	}

	rowCount, _ := res.RowsAffected()
	logger.Debug("SQL:%s ROWS:%d\n", sqlStr, rowCount)
}

// CloudEvent adds an Event to the cloudQueue for later sending to the cloud
func CloudEvent(event Event) error {
	if kernel.FlagNoCloud {
		return nil
	}
	select {
	case cloudQueue <- event:
	default:
		// log the event with the OC verb passing the counter name and the repeat message limit as the first two arguments
		logger.Warn("%OC|Cloud queue at capacity[%d]. Dropping message: %v\n", "reports_cloud_queue_full", 100, cap(cloudQueue), event)
		return errors.New("Cloud Queue at Capacity")
	}
	return nil
}

// cloudSender reads from the cloudQueue and logs the events to the cloud
func cloudSender() {
	var uid string
	var err error

	uid, err = settings.GetUID()
	if err != nil {
		uid = "00000000-0000-0000-0000-000000000000"
		logger.Warn("Unable to read UID: %s - Using all zeros\n", err.Error())
	}

	// FIXME - We disable cert checking on our http.Client for now
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: time.Duration(5 * time.Second)}
	target := fmt.Sprintf("https://database.untangle.com/v1/put?source=%s&type=db&queueName=mfw_events", uid)

	for {
		event := <-cloudQueue
		message, err := json.Marshal(event)
		if err != nil {
			logger.Warn("Error calling json.Marshal: %s\n", err.Error())
			continue
		}

		request, err := http.NewRequest("POST", target, bytes.NewBuffer(message))
		if err != nil {
			logger.Warn("Error calling http.NewRequest: %s\n", err.Error())
			continue
		}

		request.Header.Set("AuthRequest", "93BE7735-E9F2-487A-9DD4-9D05B95640F5")

		response, err := client.Do(request)
		if err != nil {
			logger.Warn("Error calling client.Do: %s\n", err.Error())
			continue
		}

		_, err = ioutil.ReadAll(response.Body)
		response.Body.Close()

		if err != nil {
			logger.Warn("Error calling ioutil.ReadAll: %s\n", err.Error())
		}

		if logger.IsDebugEnabled() {
			logger.Debug("CloudURL:%s CloudRequest:%s CloudResponse: [%d] %s %s\n", target, string(message), response.StatusCode, response.Proto, response.Status)
		}
	}
}

// prepareEventValues prepares data that should be modified when being inserted into SQLite
func prepareEventValues(data interface{}) interface{} {
	switch data.(type) {
	//IP Addresses should be converted to string types before stored in database
	case net.IP:
		return data.(net.IP).String()

	// Special handle time.Time
	// We want to log these as milliseconds since epoch
	case time.Time:
		return data.(time.Time).UnixNano() / 1e6
	default:
		return data
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
	logger.Debug("cleanupQuery(%d)\n", query.ID)
	queriesLock.Lock()
	defer queriesLock.Unlock()
	delete(queriesMap, query.ID)
	if query.Rows != nil {
		query.Rows.Close()
		query.Rows = nil
	}
	logger.Debug("cleanupQuery(%d) finished\n", query.ID)
}

// createTables builds the reports.db tables and indexes
func createTables() {
	var err error

	_, err = dbMain.Exec(
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id int8 PRIMARY KEY NOT NULL,
			time_stamp bigint NOT NULL,
			end_time bigint,
			family int1,
			ip_protocol int,
			hostname text,
			username text,
			client_interface_id int default 0,
			server_interface_id int default 0,
			client_interface_type int1 default 0,
			server_interface_type int1 default 0,
			local_address  text,
			remote_address text,
			client_address text,
			server_address text,
			client_port int2,
			server_port int2,
			client_address_new text,
			server_address_new text,
			server_port_new int2,
			client_port_new int2,
			client_country text,
			client_latitude real,
			client_longitude real,
			server_country text,
			server_latitude real,
			server_longitude real,
			application_id text,
			application_name text,
			application_protochain text,
			application_category text,
			application_blocked boolean,
			application_flagged boolean,
			application_confidence integer,
			application_productivity integer,
			application_risk integer,
			application_detail text,
			application_id_inferred text,
			application_name_inferred text,
			application_confidence_inferred integer,
			application_protochain_inferred text,
			application_productivity_inferred integer,
			application_risk_inferred text,
			application_category_inferred text,
			certificate_subject_cn text,
			certificate_subject_o text,
			ssl_sni text,
			wan_rule_chain string,
			wan_rule_id integer,
			wan_policy_id integer,
			client_hops integer,
			server_hops integer,
			client_dns_hint text,
			server_dns_hint text)`)

	if err != nil {
		logger.Err("Failed to create table: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_sessions_time_stamp ON sessions (time_stamp DESC)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_sessions_session_id_time_stamp ON sessions (session_id, time_stamp DESC)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_wan_routing ON sessions (wan_rule_chain, server_interface_type, time_stamp DESC)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_sessions_client_address ON sessions (session_id, time_stamp DESC, client_address)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_sessions_server_port ON sessions (session_id, time_stamp DESC, server_port)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_sessions_app_name ON sessions (session_id, time_stamp DESC, application_name)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_sessions_app_proto ON sessions (session_id, time_stamp DESC, application_protochain)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}
	// FIXME add domain (SNI + dns_prediction + cert_prediction)
	// We need a singular "domain" field that takes all the various domain determination methods into account and chooses the best one
	// I think the preference order is:
	//    ssl_sni (preferred because the client specified exactly the domain it is seeking)
	//    server_dns_hint (use a dns hint if no other method is known)
	//    certificate_subject_cn (preferred next as its specified by the server, but not exact, this same field is used by both certsniff and certfetch)

	// FIXME add domain_category
	// We need to add domain level categorization

	_, err = dbMain.Exec(
		`CREATE TABLE IF NOT EXISTS session_stats (
			session_id int8 NOT NULL,
			time_stamp bigint NOT NULL,
			bytes int8,
			client_bytes int8,
			server_bytes int8,
			byte_rate int8,
			client_byte_rate int8,
			server_byte_rate int8,
			packets int8,
			client_packets int8,
			server_packets int8,
			packet_rate int8,
			client_packet_rate int8,
			server_packet_rate int8)`)

	if err != nil {
		logger.Err("Failed to create table: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_session_stats_time_stamp ON session_stats (time_stamp DESC)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_session_stats_session_id_time_stamp ON session_stats (session_id, time_stamp DESC)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(
		`CREATE TABLE IF NOT EXISTS interface_stats (
			time_stamp bigint NOT NULL,
			interface_id int1,
			device_name text,
			latency_1 real,
			latency_5 real,
			latency_15 real,
			latency_variance real,
			passive_latency_1 real,
			passive_latency_5 real,
			passive_latency_15 real,
			passive_latency_variance real,
			active_latency_1 real,
			active_latency_5 real,
			active_latency_15 real,
			active_latency_variance real,
			jitter_1 real,
			jitter_5 real,
			jitter_15 real,
			jitter_variance real,
			ping_timeout int8,
			ping_timeout_rate int8,
			rx_bytes int8,
			rx_bytes_rate int8,
			rx_packets int8,
			rx_packets_rate int8,
			rx_errs int8,
			rx_errs_rate int8,
			rx_drop int8,
			rx_drop_rate int8,
			rx_fifo int8,
			rx_fifo_rate int8,
			rx_frame int8,
			rx_frame_rate int8,
			rx_compressed int8,
			rx_compressed_rate int8,
			rx_multicast int8,
			rx_multicast_rate int8,
			tx_bytes int8,
			tx_bytes_rate int8,
			tx_packets int8,
			tx_packets_rate int8,
			tx_errs int8,
			tx_errs_rate int8,
			tx_drop int8,
			tx_drop_rate int8,
			tx_fifo int8,
			tx_fifo_rate int8,
			tx_colls int8,
			tx_colls_rate int8,
			tx_carrier int8,
			tx_carrier_rate int8,
			tx_compressed,
			tx_compressed_rate int8)`)

	if err != nil {
		logger.Err("Failed to create table: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_interface_stats_time_stamp ON interface_stats (time_stamp DESC)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_ping_timeout ON interface_stats (interface_id, time_stamp DESC, ping_timeout)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_rx_bytes ON interface_stats (interface_id, time_stamp DESC, rx_bytes)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_jitter_1 ON interface_stats (interface_id, time_stamp DESC, jitter_1)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_latency ON interface_stats (interface_id, time_stamp DESC, latency_1)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_active_latency ON interface_stats (interface_id, time_stamp DESC, active_latency_1)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}

	_, err = dbMain.Exec(`CREATE INDEX idx_passive_latency ON interface_stats (interface_id, time_stamp DESC, passive_latency_1)`)
	if err != nil {
		logger.Err("Failed to create index: %s\n", err.Error())
	}
}

// addDefaultTimestampConditions adds time_stamp > X and time_stamp < Y
// to userConditions if they are not already present
func addOrUpdateTimestampConditions(reportEntry *ReportEntry) error {
	var err error
	err = addOrUpdateTimestampCondition(reportEntry, "GT", time.Now().Add(-1*time.Duration(100)*time.Hour))
	if err != nil {
		return err
	}

	err = addOrUpdateTimestampCondition(reportEntry, "LT", time.Now().Add(time.Duration(1)*time.Minute))
	if err != nil {
		return err
	}

	return nil
}

func addOrUpdateTimestampCondition(reportEntry *ReportEntry, operator string, defaultTime time.Time) error {
	var err error

	for i, cond := range reportEntry.Conditions {
		if cond.Column == "time_stamp" && cond.Operator == operator {
			var condition = &reportEntry.Conditions[i]

			// if a condition is found, set the condition value to a time.Time
			// check if its a string or int
			var timeEpochSec int64
			jsonNumber, ok := condition.Value.(json.Number)
			if ok {
				// time is specified in milliseconds, lets just use seconds
				timeEpochMillisecond, err := jsonNumber.Int64()
				timeEpochSec = timeEpochMillisecond / 1000
				if err != nil {
					logger.Warn("Invalid JSON number for time_stamp condition: %v\n", condition.Value)
					return err
				}
			} else {
				valueStr, ok := condition.Value.(string)
				if ok {
					// otherwise just convert the epoch value to a time.Time
					timeEpochSec, err = strconv.ParseInt(valueStr, 10, 64)
					if err != nil {
						logger.Warn("Invalid JSON number for time_stamp condition: %v\n", condition.Value)
						return err
					}
				}
			}

			// update value to actual Time value expected by sqlite3
			condition.Value = dateFormat(time.Unix(timeEpochSec, 0))
			return nil
		}
	}

	// if no time found, set defaultTime
	newCondition := ReportCondition{Column: "time_stamp", Operator: operator, Value: dateFormat(defaultTime)}
	reportEntry.Conditions = append(reportEntry.Conditions, newCondition)

	return nil
}

// mergeConditions moves any user specified conditions in UserConditions
// to Conditions
func mergeConditions(reportEntry *ReportEntry) {
	if len(reportEntry.UserConditions) > 0 {
		reportEntry.Conditions = append(reportEntry.Conditions, reportEntry.UserConditions...)
	}
	reportEntry.UserConditions = []ReportCondition{}
}

/**
 * dbCleaner monitors the size of the sqlite database. Once the database file grows to
 * the size limit, we begin deleting the oldest data to keep the file from growing too
 * large. Since deleting rows doesn't reduce the file size, we use the number of free
 * pages to decide when to trim the oldest data. We no longer perform a vacuum operation
 * since it is very expensive, and we don't believe it provides commensurate benefit in
 * this environment. The database is relatively small, most of the records are of similar
 * size, and it's typically stored in a memory-based filesystem, so we don't believe
 * fragmentation is a significant concern.
**/
func dbCleaner() {
	ch := make(chan bool, 1)
	ch <- true

	for {
		select {
		case <-ch:
		case <-time.After(60 * time.Second):
		}

		currentSize, pageSize, pageCount, maxPageCount, freeCount := loadDbStats()

		logger.Info("Database Size:%v MB  Limit:%v MB  Free Pages:%v Page Size: %v Page Count: %v Max Page Count: %v \n", currentSize/oneMEGABYTE, dbSizeLimit/oneMEGABYTE, freeCount, pageSize, pageCount, maxPageCount)

		// if we haven't reached the size limit just continue
		if currentSize < dbSizeLimit {
			continue
		}

		// if we haven't dropped below the minimum free page limit just continue
		if freeCount >= (dbFREEMINIMUM / pageSize) {
			continue
		}

		// database is getting full so clean out some of the oldest data
		logger.Info("Database starting trim operation\n")

		tx, err := dbMain.Begin()
		if err != nil {
			logger.Warn("Failed to begin transaction: %s\n", err.Error())
		}

		trimPercent("sessions", .10, tx)
		trimPercent("session_stats", .10, tx)
		trimPercent("interface_stats", .10, tx)

		logger.Info("Committing database trim...\n")

		// end transaction
		err = tx.Commit()
		if err != nil {
			tx.Rollback()
			logger.Warn("Failed to commit transaction: %s\n", err.Error())
		}
		logger.Info("Database trim operation completed\n")

		//also run optimize
		runSQL("PRAGMA optimize")

		logger.Info("Database trim operation completed\n")

		currentSize, pageSize, pageCount, maxPageCount, freeCount = loadDbStats()
		logger.Info("POST TRIM Database Size:%v MB  Limit:%v MB  Free Pages:%v Page Size: %v Page Count: %v Max Page Count: %v \n", currentSize/oneMEGABYTE, dbSizeLimit/oneMEGABYTE, freeCount, pageSize, pageCount, maxPageCount)
		// re-run and check size with no delay
		ch <- true
	}
}

func loadDbStats() (currentSize int64, pageSize int64, pageCount int64, maxPageCount int64, freeCount int64) {
	var err error

	// we get the page size, page count, and free list size for our limit calculations
	pageSize, err = strconv.ParseInt(runSQL("PRAGMA page_size"), 10, 64)
	if err != nil || pageSize == 0 {
		logger.Crit("Unable to parse database page_size: %v\n", err)
	}

	pageCount, err = strconv.ParseInt(runSQL("PRAGMA page_count"), 10, 64)
	if err != nil {
		logger.Crit("Unable to parse database page_count: %v\n", err)
	}

	maxPageCount, err = strconv.ParseInt(runSQL("PRAGMA max_page_count"), 10, 64)
	if err != nil {
		logger.Crit("Unable to parse database page_count: %v\n", err)
	}

	freeCount, err = strconv.ParseInt(runSQL("PRAGMA freelist_count"), 10, 64)
	if err != nil {
		logger.Crit("Unable to parse database freelist_count: %v\n", err)
	}

	currentSize = (pageSize * pageCount)

	return
}

// trimPercent trims the specified table by the specified percent (by time)
// example: trimPercent("sessions",.1) will drop the oldest 10% of events in sessions by time
func trimPercent(table string, percent float32, tx *sql.Tx) {
	logger.Info("Trimming %s by %.1f%% percent...\n", table, percent*100.0)
	sqlStr := fmt.Sprintf("DELETE FROM %s WHERE time_stamp < (SELECT min(time_stamp)+cast((max(time_stamp)-min(time_stamp))*%f as int) from %s)", table, percent, table)
	logger.Debug("Trimming DB statement:\n %s \n", sqlStr)
	res, err := tx.Exec(sqlStr)
	if err != nil {
		logger.Warn("Failed to execute transaction: %s %s\n", err.Error(), sqlStr)
	}
	logger.Debug("Log trim result: %v\n", res)
}

// runSQL runs the specified SQL and returns the result which may be nothing
// mainly used for the PRAGMA commands used to get information about the database
func runSQL(sqlStr string) string {
	var stmt *sql.Stmt
	var rows *sql.Rows
	var err error
	var result string = ""

	logger.Debug("SQL: %s\n", sqlStr)

	stmt, err = dbMain.Prepare(sqlStr)
	if err != nil {
		logger.Warn("Failed to Prepare statement: %s %s\n", err.Error(), sqlStr)
		return result
	}

	defer stmt.Close()

	rows, err = stmt.Query()
	if err != nil {
		logger.Warn("Failed to Query statement: %s %s\n", err.Error(), sqlStr)
		return result
	}

	defer rows.Close()

	// we only look at the first row returned
	if rows.Next() {
		rows.Scan(&result)
	}

	return result
}
