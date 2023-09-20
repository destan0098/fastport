package udp

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/destan0098/fastport/probes"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Scanner represents a UDP port scanner.
type Scanner struct {
	Ip     string         // IP address to scan
	Probes []probes.Probe // List of UDP probes to use
	Result chan string    // Channel to send scan results
}

// Message represents information about an open UDP port.
type Message struct {
	Port    int    // Port number
	Status  string // Status (e.g., "open" or "closed")
	hexflag string // Hexadecimal flag
}

var list []Message

// Run starts the UDP port scanning process.
func (s Scanner) Run(timeout string) {
	fmt.Println("Start UDP Check")
	timeoute, _ := strconv.Atoi(timeout)
	socketTimeout := time.Duration(timeoute) * time.Millisecond

	// If IP is IPv6
	if strings.Contains(s.Ip, ":") {
		s.Ip = "[" + s.Ip + "]"
	}

	for _, probe := range probes.Probes {
		func() {
			recv_Data := make([]byte, 32)

			c, err := net.Dial("udp", fmt.Sprint(s.Ip, ":", probe.Port))

			if err != nil {
				log.Printf("Error connecting to host '%s': %s - %s", probe.Name, s.Ip, err)
				return
			}

			defer c.Close()

			Data, err := hex.DecodeString(probe.Data)

			if err != nil {
				log.Fatalf("Error in decoding probe data. Problem probe: '%s'", probe.Name)
			}

			_, err = c.Write([]byte(Data))

			if err != nil {
				return
			}

			c.SetReadDeadline(time.Now().Add(socketTimeout))

			recv_length, err := bufio.NewReader(c).Read(recv_Data)

			if err != nil {
				return
			}

			if recv_length != 0 {
				log.Printf(" %s:%d (%s)", s.Ip, probe.Port, probe.Name)
				m := Message{probe.Port, "open", probe.Name}
				list = append(list, m)
				jso, _ := json.Marshal(list)
				week := time.Now().Weekday()
				timm := time.Now().Minute()
				week2 := fmt.Sprint(week)
				timm2 := fmt.Sprint(timm)
				if _, errf := os.Stat(s.Ip + week2 + "udpopen.json"); errf == nil {
					_ = ioutil.WriteFile(s.Ip+week2+"udpopen"+timm2+".json", jso, 0644)
				} else {
					_ = ioutil.WriteFile(s.Ip+week2+"udpopen.json", jso, 0644)
				}

				s.Result <- fmt.Sprintf("%s:%d	%s", s.Ip, probe.Port, probe.Name)
			}
		}()
	}
}
