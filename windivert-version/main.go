// PacketMaker project main.go
package main

import (
	"C"
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	WindivertInit("./x86_64/WinDivert.dll")
	Handle, err := WinDivertOpenGo("ipv6", 0, 0, 0)
	if err != nil {
		log.Fatal(err)
	}

	go RXLoop(Handle)
	TXLoop(Handle)
	WinDivertCloseGo(Handle)
}

func TXLoop(Handle uintptr) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	SrcIP := "dddd:ace:cafe::5"
	DstIP := "dddd:ace:cafe:1111:2222:3333:4444:5555"
	for {
		SrcPort := RandInt(1, 65535)
		DstPort := RandInt(1, 65535)
		err := buffer.Clear()
		if err != nil {
			log.Fatal(err)
		}

		TXAddr := WinDivertAddress{}
		TXAddr.Data = 0
		TXAddr.IfIdx = 0
		TXAddr.SubIfIdx = 0
		TXAddr.Timestamp = time.Now().UnixNano() * 100

		log.Println("Please input msg:")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		input = strings.Trim(input, "\n")
		input = strings.Trim(input, "\r")
		if input == "" {
			break
		}

		TXData := make(map[string]string)
		TXData["Timestamp"] = strconv.FormatInt(TXAddr.Timestamp/100, 10)
		TXData["Msg"] = input
		TXJson, err := json.Marshal(TXData)
		if err != nil {
			log.Fatal(err)
		}

		UDPLayer := &layers.UDP{}
		UDPLayer.SrcPort = layers.UDPPort(SrcPort)
		UDPLayer.DstPort = layers.UDPPort(DstPort)
		UDPLayer.Length = uint16(len(TXJson))

		ipv6Layer := &layers.IPv6{}
		ipv6Layer.SrcIP = net.ParseIP(SrcIP)
		ipv6Layer.DstIP = net.ParseIP(DstIP)
		ipv6Layer.Version = uint8(6)
		ipv6Layer.HopLimit = uint8(64)
		ipv6Layer.Length = uint16(UDPLayer.Length + 8)
		ipv6Layer.NextHeader = layers.IPProtocolUDP

		FakeHeader := makeUDPFakeHeader(SrcIP, DstIP, ipv6Layer.Length, SrcPort, DstPort, UDPLayer.Length)
		FakeHeaderbyte, err := hex.DecodeString(FakeHeader)
		if err != nil {
			log.Fatal(err)
		}
		UDPLayer.Checksum = checkSum(FakeHeaderbyte)

		gopacket.SerializeLayers(buffer, options, ipv6Layer, UDPLayer)
		TXPacket := append(buffer.Bytes(), TXJson...)
		log.Println(hex.EncodeToString(TXPacket))
		WinDivertHelperCalcChecksumsGo(Handle, TXPacket, TXAddr)
		err = WinDivertSendGo(Handle, TXPacket, TXAddr)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func RXLoop(Handle uintptr) {
	for true {
		RXPacket, RXAddr, err := WinDivertRecvGo(Handle)
		if err != nil {
			log.Fatal(err)
		}
		go ProcessRX(Handle, RXPacket, RXAddr)
	}
}

func ProcessRX(Handle uintptr, RXPacket []byte, RXAddr WinDivertAddress) {
	IPVersion := int(RXPacket[0] >> 4)
	var SrcIP, DstIP net.IP
	var SrcPort, DstPort string
	var ThisRXPacket gopacket.Packet
	switch IPVersion {
	case 4:
		//Do not Process At Present
		err := WinDivertSendGo(Handle, RXPacket, RXAddr)
		if err != nil {
			log.Fatal(err)
		}
		return

		ThisRXPacket = gopacket.NewPacket(RXPacket, layers.LayerTypeIPv4, gopacket.Lazy)
		IPv4Header, _ := ThisRXPacket.NetworkLayer().(*layers.IPv4)
		SrcIP = IPv4Header.SrcIP
		DstIP = IPv4Header.DstIP
	case 6:
		ThisRXPacket = gopacket.NewPacket(RXPacket, layers.LayerTypeIPv6, gopacket.Lazy)
		IPv6Header, _ := ThisRXPacket.NetworkLayer().(*layers.IPv6)
		SrcIP = IPv6Header.SrcIP
		DstIP = IPv6Header.DstIP
	}
	if ThisRXPacket.TransportLayer() != nil {
		switch ThisRXPacket.TransportLayer().LayerType() {
		case layers.LayerTypeUDP:
			UDPHeader := ThisRXPacket.TransportLayer().(*layers.UDP)
			SrcPort = UDPHeader.SrcPort.String()
			DstPort = UDPHeader.DstPort.String()
		case layers.LayerTypeTCP:
			//Do not Process At Present
			err := WinDivertSendGo(Handle, RXPacket, RXAddr)
			if err != nil {
				log.Fatal(err)
			}
			return

			TCPHeader := ThisRXPacket.TransportLayer().(*layers.TCP)
			SrcPort = TCPHeader.SrcPort.String()
			DstPort = TCPHeader.DstPort.String()
		}
	}

	if ThisRXPacket.ApplicationLayer() != nil {
		RXdata := make(map[string]string)
		err := json.Unmarshal(ThisRXPacket.ApplicationLayer().LayerContents(), &RXdata)
		if err == nil {
			log.Println("From " + SrcIP.String() + "#" + SrcPort + " to " + DstIP.String() + "#" + DstPort + " :")
			log.Println(RXdata)
			return
		}
	}
	err := WinDivertSendGo(Handle, RXPacket, RXAddr)
	if err != nil {
		log.Fatal(err)
	}
}

func RandInt(min, max int) int {
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
