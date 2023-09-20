package main

import (
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/destan0098/fastport/probes"
	tcpscanner "github.com/destan0098/fastport/scanner/tcp"
	udpscanner "github.com/destan0098/fastport/scanner/udp"
	"runtime"
	"time"
)

// maintext prints the introductory banner.
func maintext() {

	fmt.Print(color.Colorize(color.Green, `
  _____                   _        _____                                              
 |  __ \                 | |      / ____|                                             
 | |__) |   ___    _ __  | |_    | (___     ___    __ _   _ __    _ __     ___   _ __ 
 |  ___/   / _ \  | '__| | __|    \___ \   / __|  / _  | | '_ \  | '_ \   / _ \ | '__|
 | |      | (_) | | |    | |_     ____) | | (__  | (_| | | | | | | | | | |  __/ | |
 |_|       \___/  |_|     \__|   |_____/   \___|  \__,_| |_| |_| |_| |_|  \___| |_|


`))

}
func main() {
	maintext()
	runtime.GOMAXPROCS(1)

	fmt.Println("Developed By Omid For test")
	fmt.Println("Example : man.exe -ip='127.0.0.1' -proto='tcp' -timeout='1000'")
	fmt.Println("You Can Also Type In Protocol all to scan TCP AND UDP")
	ipadd := flag.String("ip", "127.0.0.1", "IP Address To scan")
	protocols := flag.String("proto", "all", "Protocol To scan")
	timeout := flag.String("timeout", "1000", "Time Out By MilliSecond")
	flag.Parse()

	if *protocols == "tcp" {
		fmt.Println("Scanning " + *ipadd + " TCP Ports")
		//tcpscanner.Tcpscanner(*ipadd, *timeout)
		tcpscanner.Tcpscanner(*ipadd, *timeout)

	} else if *protocols == "udp" {
		fmt.Println("Scanning " + *ipadd + " UDP Ports")
		time.Sleep(1 * time.Second)
		scanUDPPort(*ipadd, *timeout)
		time.Sleep(1 * time.Second)
		//	udpportscanner(*ipadd)

	} else if *protocols == "all" {
		fmt.Println("Scanning " + *ipadd + " TCP And UDP Ports")
		//tcpscanner.Tcpscanner(*ipadd, *timeout)
		tcpscanner.Tcpscanner(*ipadd, *timeout)
		time.Sleep(1 * time.Second)
		scanUDPPort(*ipadd, *timeout)
		time.Sleep(1 * time.Second)

	} else {
		fmt.Println("Enter Protocol by proto")
		fmt.Println("example to scan file.go -ip=localhost -proto=tcp")
	}

}

// scanUDPPort scans UDP ports.
func scanUDPPort(ip string, timeout string) {
	probe_count := len(probes.Probes)
	result := make(chan string, probe_count)
	scanner := udpscanner.Scanner{Ip: ip, Probes: probes.Probes, Result: result}
	scanner.Run(timeout)
	fmt.Println("Scan Done....")
}
