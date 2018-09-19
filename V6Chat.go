package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	ifmap := make(map[string]string)
	devmap := make(map[string]pcap.Interface)
	num := 1
	log.Println("Interface Found:")
	for _, device := range devices {
		log.Println(strconv.Itoa(num) + "-" + device.Description)
		ifmap[strconv.Itoa(num)] = device.Name
		devmap[device.Name] = device
		num += 1
	}
	var selectediface string
	for {
		log.Println("Please Select Interface Number:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		if err != nil {
			log.Fatal(err)
		}
		ifname, ok := ifmap[input]
		if !ok {
			continue
		} else {
			selectediface = ifname
			break
		}
	}
	ifaceaddr := devmap[selectediface].Addresses
	for addr := range ifaceaddr {
		thisaddr := ifaceaddr[addr].IP.String()
		if strings.Contains(thisaddr, ".") {
			break
		}
		log.Println(thisaddr)
	}
	handle, err := pcap.OpenLive(selectediface, 4096, true, time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter("ip6")
	if err != nil {
		log.Fatal(err)
	}
	go recv(handle)

	var options gopacket.SerializeOptions
	for {
		buffer := gopacket.NewSerializeBuffer()
		ipv6Layer := &layers.IPv6{
			SrcIP: net.ParseIP("dddd:1234:5678::2"),
			DstIP: net.ParseIP("dddd:1234:5678::3"),
		}
		log.Println("Please input msg:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		gopacket.SerializeLayers(buffer, options, &layers.Ethernet{}, ipv6Layer, gopacket.Payload([]byte(input)))
		outgoingPacket := buffer.Bytes()
		err = handle.WritePacketData(outgoingPacket)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func recv(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer == nil {
			continue
		}
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		log.Printf("From %s to %s\n", ipv6.SrcIP, ipv6.DstIP)
		log.Println(ipv6Layer.LayerPayload())
	}
}
