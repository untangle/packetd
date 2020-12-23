package reports

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-sqlite3"
	zmq "github.com/pebbe/zmq4"
	pbe "github.com/untangle/golang-shared/structs/protocolbuffers/SessionEvent"
	"github.com/untangle/packetd/services/kernel"
	"github.com/untangle/golang-shared/services/logger"
	"github.com/untangle/golang-shared/services/overseer"
	"github.com/untangle/golang-shared/services/settings"
	"google.golang.org/protobuf/proto"
	spb "google.golang.org/protobuf/types/known/structpb"
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

// the main database connection
var dbMain *sql.DB

// The queries map tracks async database requests from the admin interface. A call
// is made to CreateQuery, the results are fetched via one or more calls to
// GetData, followed by a final call to CloseQuery for cleanup.
var queriesMap = make(map[uint64]*Query)
var queriesLock sync.RWMutex
var queryID uint64

type zmqMessage struct {
	Topic   string
	Message []byte
}

var sessionChannel = make(chan *pbe.SessionEvent, 1000)
var interfaceStatsChannel = make(chan []interface{}, 1000)
var sessionStatsChannel = make(chan []interface{}, 5000)
var messageChannel = make(chan *zmqMessage, 1000)
var cloudQueue = make(chan Event, 1000)
var preparedStatements = map[string]*sql.Stmt{}
var preparedStatementsMutex = sync.RWMutex{}

const dbFILENAME = "reports.db"
const dbFILEPATH = "/tmp"

// Startup starts the reports service
func Startup() {
	var dsn string
	var err error
	sql.Register("sqlite3_custom", &sqlite3.SQLiteDriver{})

	dsn = fmt.Sprintf("file:%s/%s?mode=rwc", dbFILEPATH, dbFILENAME)
	dbMain, err = sql.Open("sqlite3_custom", dsn)
	if err != nil {
		logger.Err("Failed to open database: %s\n", err.Error())
	}

	go zmqPublisher()
	go fillMessageChannel()

	if !kernel.FlagNoCloud {
		go cloudSender()
	}
}

// Shutdown stops the reports service
func Shutdown() {
	dbMain.Close()
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

// zmqPublisher reads from the message channel and sends the events to the associated topic
func zmqPublisher() {
	socket, err := setupZmqPubSocket()
	if err != nil {
		logger.Warn("Unable to setup ZMQ Publishing socket: %s\n", err)
		return
	} else {
		defer socket.Close()
	}

	for {

		select {
		case msg := <-messageChannel:
			sentBytes, err := socket.SendMessage(msg.Topic, msg.Message)
			if err != nil {
				logger.Err("Test publisher error: %s\n", err)
				break //  Interrupted
			}
			logger.Debug("Message sent, %v bytes sent.\n", sentBytes)

		}
	}
}

// setupZmqSocket sets up the reports ZMQ socket for publishing events
func setupZmqPubSocket() (soc *zmq.Socket, err error) {
	logger.Info("Setting up ZMQ Publishing socket...\n")

	publisher, err := zmq.NewSocket(zmq.PUB)

	if err != nil {
		logger.Err("Unable to open ZMQ publisher socket: %s\n", err)
		return nil, err
	}

	err = publisher.SetLinger(0)
	if err != nil {
		logger.Err("Unable to SetLinger on ZMQ socket: %s\n", err)
		return nil, err
	}
	// TODO: We should create a common file for reportd to use,
	// with a randomized ZMQ port (something outside of normal usage ports, ie: 22,80,443,etc)
	err = publisher.Bind("tcp://*:5561")

	if err != nil {
		logger.Err("Unable to bind to ZMQ socket: %s\n", err)
		return nil, err
	}

	logger.Info("ZMQ Publisher started!\n")

	return publisher, nil
}

// fillMessageChannel parses the associated log queues, converts the data and fills the message queue
func fillMessageChannel() {
	for {
		select {
		case session := <-sessionChannel:
			sessOut, err := proto.Marshal(session)
			if err != nil {
				logger.Err("Cannot parse proto buff: %s\n", err)
				continue
			}
			messageChannel <- &zmqMessage{Topic: "untangle:packetd:sessions", Message: sessOut}
		case intf := <-interfaceStatsChannel:
			logger.Debug("Interface stats need to be parsed into a protobuffer %s\n", intf)
		case sessStats := <-sessionStatsChannel:
			logger.Debug("Session stats need to be parsed into a protobuffer %s\n", sessStats)

		}
	}
}

// CreateQuery submits a database query and returns the results
func CreateQuery(reportEntryStr string) (*Query, error) {
	var clean bool
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
	var sqlStmt *sql.Stmt

	sqlStmt, clean, err = getPreparedStatement(reportEntry)
	if err != nil {
		logger.Warn("Failed to get prepared SQL: %v\n", err)
		return nil, err
	}
	values := conditionValues(reportEntry.Conditions)

	logger.Debug("SQL Values: %v \n", values)

	rows, err = sqlStmt.Query(values...)

	// If the prepared statment was not cached the clean flag will be true which
	// means we have to close the statement so the memory can be released.
	// Check and do statement cleanup first to make the code a little cleaner
	// rather than doing it both in and following the Query error handler.
	if clean {
		sqlStmt.Close()
	}

	// now check for any error returned from sqlStmt.Query
	if err != nil {
		logger.Err("sqlStmt.Query error: %s\n", err)
		return nil, err
	}

	q := new(Query)
	q.ID = atomic.AddUint64(&queryID, 1)
	q.Rows = rows

	queriesLock.Lock()
	queriesMap[q.ID] = q
	queriesLock.Unlock()

	// I believe this is here to cleanup stray queries that may be locking the database?
	go func() {
		time.Sleep(60 * time.Second)
		cleanupQuery(q)
	}()
	return q, nil
}

// getPreparedStatement retrieves the prepared statements from the prepared statements map
// and creates it if it does not exist. This largely takes from the ideas here:
// https://thenotexpert.com/golang-sql-recipe/
// MFW-1056 added logic to detect and not cache queries that will always be unique. This
// happens with series type queries where timestamp and other values are passed inline
// rather than as placeholders that reference argumented values passed into the query.
func getPreparedStatement(reportEntry *ReportEntry) (*sql.Stmt, bool, error) {
	var stmt *sql.Stmt
	var present bool

	query, err := makeSQLString(reportEntry)
	if err != nil {
		logger.Warn("Failed to make SQL: %v\n", err)
		return nil, false, err
	}

	preparedStatementsMutex.RLock()
	if stmt, present = preparedStatements[query]; present {
		preparedStatementsMutex.RUnlock()
		return stmt, false, nil
	}

	// If not present, let's create.
	preparedStatementsMutex.RUnlock()
	// Locking for both reading and writing now.
	preparedStatementsMutex.Lock()
	defer preparedStatementsMutex.Unlock()

	// There is a tiny possibility that one goroutine creates a statement but another one gets here as well.
	// Then the latter will receive the prepared statement instead of recreating it.
	if stmt, present = preparedStatements[query]; present {
		return stmt, false, nil
	}

	stmt, err = dbMain.Prepare(query)
	if err != nil {
		return nil, false, err
	}

	// Complex UI series queries have embedded timestamps and such that make them unique so
	// we return without adding to our cache and tell the caller to do statement cleanup.
	if reportEntry.Type == "SERIES" || reportEntry.Type == "CATEGORIES_SERIES" {
		return stmt, true, nil
	}

	overseer.AddCounter("reports_prepared_statement_cache", 1)
	preparedStatements[query] = stmt
	return stmt, false, nil
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

// CreateProtoBufEvent creates a CreateProtoBufEvent type for registering in the queue
func CreateEvent(name string, table string, sqlOp int32, columns map[string]interface{}, modifiedColumns map[string]interface{}) (*pbe.SessionEvent, *Event) {

	colStruct, err := spb.NewStruct(columns)
	if err != nil {
		logger.Err("Unable to convert columns to struct: %s this is coming from: %s - %s\n", err, name, table)
		return nil, nil
	}

	modColStruct, err := spb.NewStruct(modifiedColumns)
	if err != nil {
		logger.Err("Unable to convert modifiedColumns to struct: %s this is coming from: %s - %s\n", err, name, table)
		return nil, nil
	}

	event := &pbe.SessionEvent{Name: name, Table: table, SQLOp: sqlOp, Columns: colStruct, ModifiedColumns: modColStruct}

	oldEvent := &Event{Name: name, Table: table, SQLOp: int(sqlOp), Columns: columns, ModifiedColumns: modifiedColumns}

	return event, oldEvent
}

// LogEvent adds a SessionEvent to the eventQueue for later logging
func LogEvent(pbuffEvt *pbe.SessionEvent, oldEvent *Event) error {
	// Don't add nil events into the eventQueue
	if pbuffEvt == nil {
		return nil
	}

	select {
	case sessionChannel <- pbuffEvt:
	default:
		// log the message with the OC verb passing the counter name and the repeat message limit as the first two arguments
		logger.Warn("%OC|SessionEvent queue at capacity[%d]. Dropping event\n", "reports_event_queue_full", 100, cap(sessionChannel))
		return errors.New("SessionEvent Queue at Capacity")
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

	for i := 0; i < limit && rows.Next(); i++ {
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

// LogInterfaceStats is called to insert a row into the interface_stats database table
func LogInterfaceStats(values []interface{}, isWan bool) {
	// TODO: send to ZMQ, move cloud logging to ZMQ processor
	select {
	case interfaceStatsChannel <- values:
	default:
		// log the message with the OC verb passing the counter name and the repeat message limit as the first two arguments
		logger.Warn("%OC|interfaceStatsQueue at capacity[%d]. Dropping event\n", "reports_interface_stats_overrun", 100, cap(interfaceStatsChannel))
	}

	// if the no-cloud flag is set or not a WAN interface do not send to cloud
	// if kernel.FlagNoCloud || !isWan {
	// 	return
	// }

	// // create an event we can send to the cloud
	// columns := make(map[string]interface{})
	// namelist := GetInterfaceStatsColumnList()

	// // build a columns map using the column list and argumented values
	// for x := 0; x < len(values); x++ {
	// 	name := namelist[x]
	// 	columns[name] = values[x]
	// }

	// create the event and put it in the cloud queue
	//event := CreateEvent("interface_stats", "interface_stats", 1, columns, nil)

	//	select {
	//	case cloudQueue <- event:
	//	default:
	// log the event with the OC verb passing the counter name and the repeat message limit as the first two arguments
	//		logger.Warn("%OC|Cloud queue at capacity[%d]. Dropping message\n", "reports_cloud_queue_full", 100, cap(cloudQueue))
	//	}
}

// LogSessionStats is called to insert a sessionStats protocol buffer into the sessionStatsChannel
func LogSessionStats(values []interface{}) {

	// TODO: send to ZMQ
	select {
	case sessionStatsChannel <- values:
	default:
		// log the message with the OC verb passing the counter name and the repeat message limit as the first two arguments
		logger.Warn("%OC|sessionStatsQueue at capacity[%d]. Dropping event\n", "reports_session_stats_overrun", 100, cap(interfaceStatsChannel))
	}
}
