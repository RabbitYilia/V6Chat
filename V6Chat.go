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
		log.Println("Please input msg:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		UDPLayer := &layers.UDP{}
		UDPLayer.SrcPort = layers.UDPPort(8888)
		UDPLayer.DstPort = layers.UDPPort(9999)
		UDPLayer.Length = uint16(len([]byte(input)))
		ipv6Layer := &layers.IPv6{}
		ipv6Layer.Version = uint8(6)
		ipv6Layer.SrcIP = net.ParseIP("dddd:1234:5678::2")
		ipv6Layer.DstIP = net.ParseIP("dddd:1234:5678::3")
		ipv6Layer.HopLimit = uint8(64)
		ipv6Layer.Length = uint16(len([]byte(input)) + 8)
		ipv6Layer.NextHeader = layers.IPProtocolUDP
		EtherLayer := &layers.Ethernet{}
		EtherLayer.SrcMAC = net.HardwareAddr{0x00, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
		EtherLayer.DstMAC = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
		EtherLayer.EthernetType = layers.EthernetTypeIPv6
		gopacket.SerializeLayers(buffer, options, EtherLayer, ipv6Layer, UDPLayer, gopacket.Payload([]byte(input)))
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
