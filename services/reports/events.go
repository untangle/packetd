package reports

/*
These functions provide the low level framework for capturing session and
interface stats in the system database. This data is used to display
the dashboard and other session details in the management interface.

The GetxxxColumnList functions return the list of columns in the corresponding
table in the order they appear in the prepared INSERT statment. When logging these
events to the database, the values MUST be appended to the values interface array
in this order so the correct values are written to the corresponding columns.

The GetxxxInsertQuery functions return a string generated using the GetxxxColumnList
function that is used to create the prepared statement for inserting each event
type in the database.
*/

// GetInterfaceStatsColumnList returns the columns in the interface_stats database table
func GetInterfaceStatsColumnList() []string {
	return []string{
		"time_stamp",
		"interface_id",
		"interface_name",
		"device_name",
		"is_wan",
		"latency_1",
		"latency_5",
		"latency_15",
		"latency_variance",
		"passive_latency_1",
		"passive_latency_5",
		"passive_latency_15",
		"passive_latency_variance",
		"active_latency_1",
		"active_latency_5",
		"active_latency_15",
		"active_latency_variance",
		"jitter_1",
		"jitter_5",
		"jitter_15",
		"jitter_variance",
		"ping_timeout",
		"ping_timeout_rate",
		"rx_bytes",
		"rx_bytes_rate",
		"rx_packets",
		"rx_packets_rate",
		"rx_errs",
		"rx_errs_rate",
		"rx_drop",
		"rx_drop_rate",
		"rx_fifo",
		"rx_fifo_rate",
		"rx_frame",
		"rx_frame_rate",
		"rx_compressed",
		"rx_compressed_rate",
		"rx_multicast",
		"rx_multicast_rate",
		"tx_bytes",
		"tx_bytes_rate",
		"tx_packets",
		"tx_packets_rate",
		"tx_errs",
		"tx_errs_rate",
		"tx_drop",
		"tx_drop_rate",
		"tx_fifo",
		"tx_fifo_rate",
		"tx_colls",
		"tx_colls_rate",
		"tx_carrier",
		"tx_carrier_rate",
		"tx_compressed",
		"tx_compressed_rate",
	}
}

// GetInterfaceStatsInsertQuery generates the SQL for creating the prepared INSERT statment for the interface_stats table
func GetInterfaceStatsInsertQuery() string {
	colList := GetInterfaceStatsColumnList()
	sqlStr := "INSERT INTO interface_stats ("
	valStr := "("

	for x := 0; x < len(colList); x++ {
		if x != 0 {
			sqlStr += ","
			valStr += ","
		}
		sqlStr += colList[x]
		valStr += "?"
	}

	sqlStr += ")"
	valStr += ")"
	return (sqlStr + " VALUES " + valStr)
}

// GetSessionStatsColumnList returns the list of columns in the session_stats table
func GetSessionStatsColumnList() []string {
	return []string{
		"time_stamp",
		"session_id",
		"bytes",
		"byte_rate",
		"client_bytes",
		"client_byte_rate",
		"server_bytes",
		"server_byte_rate",
		"packets",
		"packet_rate",
		"client_packets",
		"client_packet_rate",
		"server_packets",
		"server_packet_rate",
	}
}

// GetSessionStatsInsertQuery generates the SQL for creating the prepared INSERT statement for the session_stats table
func GetSessionStatsInsertQuery() string {
	colList := GetSessionStatsColumnList()
	sqlStr := "INSERT INTO session_stats ("
	valStr := "("

	for x := 0; x < len(colList); x++ {
		if x != 0 {
			sqlStr += ","
			valStr += ","
		}
		sqlStr += colList[x]
		valStr += "?"
	}

	sqlStr += ")"
	valStr += ")"
	return (sqlStr + " VALUES " + valStr)
}
