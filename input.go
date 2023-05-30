package zgrab2

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nsqio/go-nsq"
	log "github.com/sirupsen/logrus"
)

// ParseCSVTarget takes a record from a CSV-format input file and
// returns the specified ipnet, domain, and tag, or an error.
//
// ZGrab2 input files have three fields:
// IP, DOMAIN, TAG
//
// Each line specifies a target to scan by its IP address, domain
// name, or both, as well as an optional tag used to determine which
// scanners will be invoked.
//
// A CIDR block may be provided in the IP field, in which case the
// framework expands the record into targets for every address in the
// block.
//
// Trailing empty fields may be omitted.
// Comment lines begin with #, and empty lines are ignored.
func ParseCSVTarget(fields []string) (ipnet *net.IPNet, domain string, tag string, err error) {
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) > 0 && fields[0] != "" {
		if ip := net.ParseIP(fields[0]); ip != nil {
			ipnet = &net.IPNet{IP: ip}
		} else if _, cidr, er := net.ParseCIDR(fields[0]); er == nil {
			ipnet = cidr
		} else if len(fields) != 1 {
			err = fmt.Errorf("can't parse %q as an IP address or CIDR block", fields[0])
			return
		}
	}
	if len(fields) > 1 {
		domain = fields[1]
	}
	if len(fields) > 2 {
		tag = fields[2]
	}
	if len(fields) > 3 {
		err = fmt.Errorf("too many fields: %q", fields)
		return
	}

	// For legacy reasons, we also allow targets of the form:
	// DOMAIN
	if ipnet == nil && len(fields) == 1 {
		domain = fields[0]
	}

	if ipnet == nil && domain == "" {
		err = fmt.Errorf("record doesn't specify an address, network, or domain: %v", fields)
		return
	}
	return
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func duplicateIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

type ZGrabMetadata struct {
	ScanAfter string `json:"scan_after"`
	CertSHA1  string `json:"cert_sha1"`
	CertType  string `json:"cert_type"`
}

type Input struct {
	Domain   string        `json:"sni"`
	IP       string        `json:"ip"`
	Metadata ZGrabMetadata `json:"metadata"`
	Tag      string        `json:"tag"`
}

func parseInputLine(line string) (ipnet *net.IPNet, domain string, tag string, metadata ZGrabMetadata) {
	var input Input
	err := json.Unmarshal([]byte(line), &input)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}
	if ip := net.ParseIP(input.IP); ip != nil {
		ipnet = &net.IPNet{IP: ip}
	}
	domain = input.Domain
	metadata = input.Metadata
	tag = input.Tag
	return
}

func checkScanAfter(ScanAfter string) int64 {
	scanAfter, _ := strconv.ParseInt(ScanAfter, 0, 64)
	if scanAfter > 0 {
		tnow := time.Now().Unix()
		if tnow < scanAfter {
			return scanAfter - tnow
		}
	}
	return 0
}

func InputTargetsNSQWriterFunc(nsqHost string) InputTargetsFunc {
	return func(ch chan<- ScanTarget) error {
		return InputTargetsNSQStream(nsqHost, ch)
	}
}

func InputTargetsNSQStream(nsqHost string, ch chan<- ScanTarget) error {
	// Instantiate a consumer that will subscribe to the provided channel.
	consumer, err := nsq.NewConsumer(config.NSQInputTopic, "done", nsq.NewConfig())
	if err != nil {
		log.Fatal(err)
		return err
	}
	consumer.SetLoggerLevel(nsq.LogLevelError)

	// Set the Handler for messages received by this Consumer. Can be called multiple times.
	// See also AddConcurrentHandlers.
	consumer.AddHandler(nsq.HandlerFunc(func(m *nsq.Message) error {
		// handle the message
		ipnet, domain, tag, metadata := parseInputLine(string(m.Body))
		tsleep := checkScanAfter(metadata.ScanAfter)
		if tsleep > 0 {
			m.RequeueWithoutBackoff(time.Duration(tsleep) * time.Second)
			log.Info("Requeue-ing message with a delay of: ", tsleep)
			return nil
		}
		var ip net.IP
		if ipnet != nil {
			if ipnet.Mask != nil {
				// expand CIDR block into one target for each IP
				for ip = ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
					ch <- ScanTarget{IP: duplicateIP(ip), Domain: domain, Tag: tag}
				}
			} else {
				ip = ipnet.IP
			}
		}
		ch <- ScanTarget{IP: ip, Domain: domain, Metadata: metadata, Tag: tag}
		return nil
	}))

	// Use nsqlookupd to discover nsqd instances.
	// See also ConnectToNSQD, ConnectToNSQDs, ConnectToNSQLookupds.
	nsqUrl := fmt.Sprintf("%s:4161", nsqHost)
	err = consumer.ConnectToNSQLookupd(nsqUrl)
	if err != nil {
		log.Fatal(err)
	}

	// wait for signal to exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Gracefully stop the consumer.
	consumer.Stop()

	return nil
}

// InputTargetsCSV is an InputTargetsFunc that calls GetTargetsCSV with
// the CSV file provided on the command line.
func InputTargetsCSV(ch chan<- ScanTarget) error {
	return GetTargetsCSV(config.inputFile, ch)
}

// GetTargetsCSV reads targets from a CSV source, generates ScanTargets,
// and delivers them to the provided channel.
func GetTargetsCSV(source io.Reader, ch chan<- ScanTarget) error {
	csvreader := csv.NewReader(source)
	csvreader.Comment = '#'
	csvreader.FieldsPerRecord = -1 // variable
	for {
		fields, err := csvreader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if len(fields) == 0 {
			continue
		}
		ipnet, domain, tag, err := ParseCSVTarget(fields)
		if err != nil {
			log.Errorf("parse error, skipping: %v", err)
			continue
		}
		var ip net.IP
		if ipnet != nil {
			if ipnet.Mask != nil {
				// expand CIDR block into one target for each IP
				for ip = ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
					ch <- ScanTarget{IP: duplicateIP(ip), Domain: domain, Tag: tag}
				}
				continue
			} else {
				ip = ipnet.IP
			}
		}
		ch <- ScanTarget{IP: ip, Domain: domain, Tag: tag}
	}
	return nil
}

// InputTargetsFunc is a function type for target input functions.
//
// A function of this type generates ScanTargets on the provided
// channel.  It returns nil if there are no further inputs or error.
type InputTargetsFunc func(ch chan<- ScanTarget) error
