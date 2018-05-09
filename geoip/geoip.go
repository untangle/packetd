package geoip

import "sync"
import "github.com/untangle/packetd/support"
import "github.com/oschwald/geoip2-golang"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "github.com/untangle/packetd/conndict"

var geodb *geoip2.Reader

/*---------------------------------------------------------------------------*/
func Plugin_Startup(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Startup(%s) has been called\n", "geoip")

	db, err := geoip2.Open("/var/cache/untangle-geoip/GeoLite2-City.mmdb")
	if err != nil {
		support.LogMessage("Unable to load GeoIP Database: %s\n", err)
	} else {
		geodb = db
	}

	childsync.Add(1)
}

/*---------------------------------------------------------------------------*/
func Plugin_Goodbye(childsync *sync.WaitGroup) {
	support.LogMessage("Plugin_Goodbye(%s) has been called\n", "geoip")
	geodb.Close()
	childsync.Done()
}

/*---------------------------------------------------------------------------*/
func Plugin_netfilter_handler(ch chan<- int32, buffer []byte, length int, ctid uint) {
	var SrcCode string = "XX"
	var DstCode string = "XX"

	support.LogMessage("GEOIP RECEIVED %d BYTES\n", length)
	packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		addr := ipLayer.(*layers.IPv4)
		SrcRecord, err := geodb.City(addr.SrcIP)
		if (err == nil) && (len(SrcRecord.Country.IsoCode) != 0) {
			SrcCode = SrcRecord.Country.IsoCode
			support.LogMessage("SRC: %s = %s\n", addr.SrcIP, SrcCode)
		}
		DstRecord, err := geodb.City(addr.DstIP)
		if (err == nil) && (len(DstRecord.Country.IsoCode) != 0) {
			DstCode = DstRecord.Country.IsoCode
			support.LogMessage("DST: %s = %s\n", addr.DstIP, DstCode)
		}
	}

	errc := conndict.Set_pair("Client Country", SrcCode, ctid)
	if (errc != nil) {
		support.LogMessage("Set_pair(client) ERROR: %s\n", errc)
	} else {
		support.LogMessage("Set_pair(client) %d = %s\n",ctid, SrcCode)
	}

	errs := conndict.Set_pair("Server Country", DstCode, ctid)
	if (errs != nil) {
		support.LogMessage("Set_pair(server) ERROR: %s\n", errs)
	} else {
		support.LogMessage("Set_pair(server) %d = %s\n",ctid, DstCode)
	}

	ch <- 4
}

/*---------------------------------------------------------------------------*/
