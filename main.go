package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gosnmp/gosnmp"
)

func main() {
	// Define command-line flags with default values.
	// These allow you to specify the target, port, and community from the command line.
	target := flag.String("target", "127.0.0.1", "The IP address or hostname of the SNMP trap receiver.")
	sourceIp := flag.String("source-ip", "127.0.0.1", "The source IP address to include in the SNMP trap's AgentAddress field.")
	port := flag.Uint("port", 162, "The port number of the SNMP trap receiver.")
	community := flag.String("community", "public", "The SNMP community string.")
	count := flag.Uint("count", 1, "The number of SNMP Traps to send.")
	rate := flag.Uint("rate", 1, "The rate of SNMP Traps per second to send.")

	// Parse the command-line flags. This must be called before using the flag variables.
	flag.Parse()

	// Create a new GoSNMP struct to configure the session.
	// This struct holds all the necessary settings for the SNMP communication.
	snmp := &gosnmp.GoSNMP{
		// Use the values parsed from the command-line flags.
		Target:    *target,
		Port:      uint16(*port),
		Community: *community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   0,
	}

	// Connect to the target SNMP agent.
	// This establishes the network connection before sending the trap.
	err := snmp.Connect()
	if err != nil {
		log.Fatalf("Connect() failed: %v", err)
	}
	defer snmp.Conn.Close()

	// The SNMP v2c ColdStart trap OID.
	// This OID identifies the type of trap being sent.
	coldStartTrapOID := ".1.3.6.1.6.3.1.1.5.1"

	// Create a PDU (Protocol Data Unit) for the trap.
	// For V2c traps, the SnmpTrapOID.0 variable binding is mandatory.
	// The sysUpTime.0 variable binding is automatically added by the gosnmp.SendTrap method.
	trapPDU := gosnmp.SnmpTrap{
		// In V2c, the trap type is defined by the SnmpTrapOID.0 variable binding.
		// The `Enterprise` field is not required for V2c. We set it to a placeholder value.
		Enterprise:   coldStartTrapOID,
		AgentAddress: *sourceIp,
		Variables: []gosnmp.SnmpPDU{
			{
				Name:  ".1.3.6.1.6.3.1.1.4.1.0", // This is the SnmpTrapOID.0 OID
				Type:  gosnmp.ObjectIdentifier,
				Value: coldStartTrapOID,
			},
		},
	}

	fmt.Printf("Sending %d SNMP v2c ColdStart traps...\n", *count)

	// Record the start time to measure performance.
	startTime := time.Now()
	var sleep = uint(1000) / *rate

	for i := uint(1); i <= *count; i++ {
		// Send the trap to the configured target.
		// The SendTrap method handles the encoding and network transmission.
		_, err = snmp.SendTrap(trapPDU)
		time.Sleep(time.Duration(sleep) * time.Millisecond)
		if err != nil {
			// Log a non-fatal error to continue sending other traps.
			log.Printf("SendTrap() failed for iteration %d: %v", i, err)
		}
	}

	// Calculate the duration.
	duration := time.Since(startTime)

	fmt.Printf("Finished sending %d traps with %d traps per second in %s to %s:%d using community %s\n", *count, *rate, duration, *target, *port, *community)
}
