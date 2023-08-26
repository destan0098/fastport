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

type Scanner struct {
	Ip     string
	Probes []probes.Probe

	Result chan string
}
type Message struct {
	Port    int
	Status  string
	hexflag string
}

var list []Message

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
				//		log.Printf("[+] Received packet: %s...", hex.EncodeToString(recv_Data))

				s.Result <- fmt.Sprintf("%s:%d	%s", s.Ip, probe.Port, probe.Name)
			}
		}()
	}
}
