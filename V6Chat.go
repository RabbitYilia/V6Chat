package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log"
	"math/rand"
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
		SrcIPv6 := "dddd:1234:5678::2"
		DstIPv6 := "dddd:1234:5678::3"
		SrcPort := RandPort(1, 65535)
		DstPort := RandPort(1, 65535)
		buffer := gopacket.NewSerializeBuffer()
		log.Println("Please input msg:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		if input == "" {
			break
		}
		UDPLayer := &layers.UDP{}
		UDPLayer.SrcPort = layers.UDPPort(SrcPort)
		UDPLayer.DstPort = layers.UDPPort(DstPort)
		UDPLayer.Length = uint16(len([]byte(input)))

		ipv6Layer := &layers.IPv6{}
		ipv6Layer.SrcIP = net.ParseIP(SrcIPv6)
		ipv6Layer.DstIP = net.ParseIP(DstIPv6)
		ipv6Layer.Version = uint8(6)
		ipv6Layer.HopLimit = uint8(64)
		ipv6Layer.Length = uint16(len([]byte(input)) + 8)
		ipv6Layer.NextHeader = layers.IPProtocolUDP
		EtherLayer := &layers.Ethernet{}
		EtherLayer.SrcMAC = net.HardwareAddr{0x00, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
		EtherLayer.DstMAC = net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD}
		EtherLayer.EthernetType = layers.EthernetTypeIPv6
		FakeHeader := makeUDPFakeHeader(SrcIPv6, DstIPv6, ipv6Layer.Length, SrcPort, DstPort, UDPLayer.Length)
		FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
		if err != nil {
			log.Fatal(err)
		}
		UDPLayer.Checksum = checkSum(FakeHeaderbyte)
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

func RandPort(min, max int) int {
	rand.Seed(time.Now().UnixNano() * rand.Int63n(100))
	return min + rand.Intn(max-min+1)
}

func makeUDPFakeHeader(SrcIPv6 string, DstIPv6 string, v6len uint16, SrcPort int, DstPort int, udplen uint16) string {
	UDPFakeHeader := ""
	FakeUDPSrc, err := net.ParseIP(SrcIPv6).MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	FakeUDPDst, err := net.ParseIP(DstIPv6).MarshalText()
	if err != nil {
		log.Fatal(err)
	}
	var convbuffer bytes.Buffer
	err = binary.Write(&convbuffer, binary.BigEndian, uint8(0))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(FakeUDPSrc)
	UDPFakeHeader += hex.EncodeToString(FakeUDPDst)
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint8(17))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, v6len)
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(SrcPort))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(DstPort))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, udplen)
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	err = binary.Write(&convbuffer, binary.LittleEndian, uint16(0))
	if err != nil {
		log.Fatal(err)
	}
	UDPFakeHeader += hex.EncodeToString(convbuffer.Bytes())
	convbuffer.Reset()
	return UDPFakeHeader
}

func checkSum(msg []byte) uint16 {
	sum := 0
	for n := 1; n < len(msg)-1; n += 2 {
		sum += int(msg[n])*256 + int(msg[n+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	var ans = uint16(^sum)
	return ans
}
