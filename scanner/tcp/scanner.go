package tcp

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type Message struct {
	Port    int
	Status  string
	hexflag string
}

var list []Message
var list2 []Message
var count = 0
var faildcount = 0

func Tcpscanner(ip string, timeout string) {
	fmt.Println(ip)
	fmt.Println("Start TCP Check")
	runtime.GOMAXPROCS(1)
	timeoute, _ := strconv.Atoi(timeout)

	var wg sync.WaitGroup

	wg.Add(65535)
	for i := 1; i <= 65535; i++ {

		go func(j int) {

			address := net.JoinHostPort(ip, strconv.Itoa(j))

			conf := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			}

			conn2, err2 := tls.Dial("tcp", address, conf)
			if err2 != nil {
				faildcount++
			} else {

				count++
				err := conn2.SetDeadline(time.Now().Add(time.Duration(timeoute) * time.Millisecond))
				if err != nil {

					recover()
				}
				var btt2 []byte
				//	fmt.Fprintf(conn, "GET / HTTP/1.1 \n")
				fmt.Fprintf(conn2, "GET / HTTP/1.1 \n")
				//fmt.Fprintf(conn2, "Hello ACK")
				//	fmt.Fprintf(conn, "SYN/ACK \n")
				btt2, err = bufio.NewReader(conn2).ReadBytes('%')

				if err != nil {

					recover()
				}

				strdec := string(btt2)

				err = conn2.Close()
				if err != nil {
					return
				}
				var re = regexp.MustCompile(`(?m)(?:[\n\r\w\W]+)[\n\r]{2}`)
				//var re = regexp.MustCompile(`(?s)Server:(.*?)\n`)
				for _, match := range re.FindAllString(strdec, -1) {
					//fmt.Println(match, "found at index", ik)
					math2 := match + "\n\r"
					fmt.Println("[+]Port ", j, " Opened with ", math2, " Service")

					m2 := Message{j, "open", math2}

					list = append(list, m2)
				}
			}
			conn, err := net.Dial("tcp", address)
			if err != nil {
				faildcount++

			} else {
				count++
				err = conn.SetDeadline(time.Now().Add(time.Duration(timeoute) * time.Second))
				if err != nil {

					recover()
				}
				var btt []byte
				fmt.Fprintf(conn, "GET / HTTP/1.1 \n")
				//	fmt.Fprintf(conn, "Hello ACK")
				//	fmt.Fprintf(conn, "SYN/ACK \n")
				btt, err = bufio.NewReader(conn).ReadBytes('%')

				if err != nil {

					recover()
				}

				strdec := string(btt)

				err = conn.Close()
				if err != nil {
					return
				}
				var re = regexp.MustCompile(`(?m)(?:[\n\r\w\W]+)[\n\r]{2}`)
				//	var re = regexp.MustCompile(`(?s)Server:(.*?)\n`)
				for _, match := range re.FindAllString(strdec, -1) {
					//fmt.Println(match, "found at index", ik)
					math2 := match + "\n\r"
					fmt.Println("[+]Port ", j, " Opened with ", math2, " Service")

					m2 := Message{j, "open", math2}

					list = append(list, m2)
				}
				/*	fmt.Println("[+]Port ", j, " Opened with ", strdec, " Service")
					m := Message{j, "open", strdec}*/

				//	list = append(list, m)

			}
			defer wg.Done()

		}(i)

	}
	wg.Wait()
	fmt.Println("success count :" + strconv.Itoa(count/2))
	fmt.Println("faild count :" + strconv.Itoa(faildcount/2))
	fmt.Println("TCP Scan Done...")
	jso, _ := json.Marshal(list)

	week := time.Now().Weekday()
	timm := time.Now().Minute()
	week2 := fmt.Sprint(week)
	timm2 := fmt.Sprint(timm)
	if _, errf := os.Stat(ip + week2 + "tcpopen.json"); errf == nil {
		_ = ioutil.WriteFile(ip+week2+"tcpopen"+timm2+".json", jso, 0644)
	} else {
		_ = ioutil.WriteFile(ip+week2+"tcpopen.json", jso, 0644)
	}

}
