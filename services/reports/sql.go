package reports

import (
	"errors"
	"fmt"
	//	"github.com/untangle/packetd/services/logger"
	"time"
)

func makeSqlString(reportEntry *ReportEntry, startTime time.Time, endTime time.Time) (string, error) {
	if reportEntry.Type == "TEXT" {
		return makeTextSqlString(reportEntry, startTime, endTime)
	} else if reportEntry.Type == "EVENTS" {
		return makeEventsSqlString(reportEntry, startTime, endTime)
	} else if reportEntry.Type == "CATEGORY" {
		return makeCategorySqlString(reportEntry, startTime, endTime)
	} else {
		// FIXME add other report types
		return "", errors.New("Unsupported reportEntry type")
	}
}

func makeTextSqlString(reportEntry *ReportEntry, startTime time.Time, endTime time.Time) (string, error) {
	sqlStr := "SELECT"
	for i, column := range reportEntry.QueryText.TextColumns {
		if i == 0 {
			sqlStr += " " + escape(column)
		} else {
			sqlStr += ", " + escape(column)
		}
	}
	sqlStr += " FROM"
	sqlStr += " " + escape(reportEntry.Table)
	sqlStr += " WHERE " + timeStampConditions(startTime, endTime)
	return sqlStr, nil
}

func makeEventsSqlString(reportEntry *ReportEntry, startTime time.Time, endTime time.Time) (string, error) {
	sqlStr := "SELECT * FROM"
	sqlStr += " " + escape(reportEntry.Table)
	sqlStr += " WHERE " + timeStampConditions(startTime, endTime)
	return sqlStr, nil
}

func makeCategorySqlString(reportEntry *ReportEntry, startTime time.Time, endTime time.Time) (string, error) {
	if reportEntry.QueryCategories.CategoriesGroupColumn == "" {
		return "", errors.New("Missing required attribute categoriesGroupColumn")
	}
	if reportEntry.QueryCategories.CategoriesAggregation == "" {
		return "", errors.New("Missing required attribute categoriesAggregation")
	}
	var orderByColumn int = 2
	if reportEntry.QueryCategories.CategoriesOrderByColumn < 0 || reportEntry.QueryCategories.CategoriesOrderByColumn > 2 {
		return "", errors.New("Illegal value for categoriesOrderByColumn")
	}
	if reportEntry.QueryCategories.CategoriesOrderByColumn != 0 {
		orderByColumn = reportEntry.QueryCategories.CategoriesOrderByColumn
	}
	var order string = "DESC"
	if reportEntry.QueryCategories.CategoriesOrderAsc {
		order = "ASC"
	}

	sqlStr := "SELECT"
	sqlStr += " " + escape(reportEntry.QueryCategories.CategoriesGroupColumn)
	sqlStr += ", " + escape(reportEntry.QueryCategories.CategoriesAggregation) + " as value"
	sqlStr += " FROM " + escape(reportEntry.Table)
	sqlStr += " WHERE " + timeStampConditions(startTime, endTime)
	sqlStr += " GROUP BY " + escape(reportEntry.QueryCategories.CategoriesGroupColumn)
	sqlStr += fmt.Sprintf(" ORDER BY %d %s", orderByColumn, order)

	if reportEntry.QueryCategories.CategoriesLimit != 0 {
		sqlStr += fmt.Sprintf(" LIMIT %d", reportEntry.QueryCategories.CategoriesLimit)
	}
	return sqlStr, nil
}

// return the SQL conditions/fragment to limit the time_stamp
// to the specified startTime and endTime
func timeStampConditions(startTime time.Time, endTime time.Time) string {
	//startTimeStr := startTime.Format("yyyy-MM-dd HH:mm:ss")
	startTimeStr := startTime.Format(time.RFC3339)
	endTimeStr := endTime.Format(time.RFC3339)
	return fmt.Sprintf("time_stamp > '%s' AND time_stamp < '%s'", startTimeStr, endTimeStr)
}

// escape escapes quotes in as string
// this is a really gross way to handle SQL safety
// https://github.com/golang/go/issues/18478
func escape(source string) string {
	var j int
	if len(source) == 0 {
		return ""
	}
	tempStr := source[:]
	desc := make([]byte, len(tempStr)*2)
	for i := 0; i < len(tempStr); i++ {
		flag := false
		var escape byte
		switch tempStr[i] {
		case '\r':
			flag = true
			escape = '\r'
			break
		case '\n':
			flag = true
			escape = '\n'
			break
		case '\\':
			flag = true
			escape = '\\'
			break
		case '\'':
			flag = true
			escape = '\''
			break
		case '"':
			flag = true
			escape = '"'
			break
		case '\032':
			flag = true
			escape = 'Z'
			break
		default:
		}
		if flag {
			desc[j] = '\\'
			desc[j+1] = escape
			j = j + 2
		} else {
			desc[j] = tempStr[i]
			j = j + 1
		}
	}
	return string(desc[0:j])
}
