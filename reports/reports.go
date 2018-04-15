package reports

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"sync/atomic"
	"time"
)

var db *sql.DB
var queries map[uint64]*Query = make(map[uint64]*Query)
var queryId uint64 = 0

type Query struct {
	Id   uint64
	Rows *sql.Rows
}

func ConnectDb() {
	var err error
	db, err = sql.Open("sqlite3", "/tmp/reports.db")

	if err != nil {
		log.Fatal(err)
	}
}

func CreateQuery(reportEntry string) (*Query, error) {
	rows, err := db.Query("SELECT * FROM sessions LIMIT 5")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	q := new(Query)
	q.Id = atomic.AddUint64(&queryId, 1)
	q.Rows = rows

	queries[q.Id] = q
	go cleanupQuery(q)
	return q, nil
}

func GetData(queryId uint64) (string, error) {
	q := queries[queryId]
	if q == nil {
		fmt.Println("Query not found: ", queryId)
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
	fmt.Println("cleanupQuery() launched ", query.Id)
	time.Sleep(30 * time.Second)
	delete(queries, query.Id)
	if query.Rows != nil {
		query.Rows.Close()
	}
	fmt.Println("cleanupQuery() finished ", query.Id)

}
