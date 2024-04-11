package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    snapshotLen int32 = 1599
    promiscuous bool  = false
    err         error
    timeout     time.Duration = pcap.BlockForever


    bytes = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "dnetexporter_bytes_total",
            Help: "Total number of bytes observed for IP pairs, including ports, by direction.",
        },
        []string{"source", "destination", "destination_port", "direction"},
    )
    packets = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "dnetexporter_packet_total",
            Help: "Total number of packets observed for IP pairs, including ports, by direction.",
        },
        []string{"source", "destination", "destination_port", "direction"},
    )


    ipPairActivities = make(map[string]ipPairActivity)
    activityMutex    sync.Mutex
    metricsTimeout   = time.Minute * 1
    srcIP string
    dstIP string
)

type ipPairActivity struct {
    LastActivity time.Time
}
type Config struct {
    Device  string `json:"device"`
    IPPairs []struct {
        Source      string `json:"source"`
        Destination string `json:"destination"`
    } `json:"ipPairs"`
}

var config Config
func readConfig() {
    file, err := ioutil.ReadFile("config.json")
    if err != nil {
        log.Fatalf("Failed to read config file: %v", err)
    }
    err = json.Unmarshal(file, &config)
    if err != nil {
        log.Fatalf("Failed to unmarshal config JSON: %v", err)
    }
}

func capturePackets(handle *pcap.Handle) {
    if err != nil {
        log.Fatalf("Could not open device %s: %v", config.Device, err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        networkLayer := packet.NetworkLayer()
        transportLayer := packet.TransportLayer()
        if networkLayer == nil || transportLayer == nil {
            continue
        }

        srcIP = networkLayer.NetworkFlow().Src().String()
        dstIP = networkLayer.NetworkFlow().Dst().String()

        var dstPort string
// var srcPort, srcportType string
        switch tLayer := transportLayer.(type) {
        case *layers.TCP:
            dstPort = strconv.Itoa(int(tLayer.DstPort))
        case *layers.UDP:
            dstPort = strconv.Itoa(int(tLayer.DstPort))
        default:
            continue // If it's neither TCP nor UDP, skip
        }
        for _, pair := range config.IPPairs {
            if isBidirectionalPair(srcIP, dstIP, pair) {
// Determine direction for labeling
                direction := "forward"
                if matchIPorSubnet(dstIP, pair.Source) && matchIPorSubnet(srcIP, pair.Destination) {
                    direction = "backward"
                }
// Update packet metrics considering direction
                labelValues := prometheus.Labels{
                    "source":          srcIP,
                    "destination":     dstIP,
                    "destination_port": dstPort,
                    "direction":       direction, 
                }
                bytes.With(labelValues).Add(float64(len(packet.Data())))
                packets.With(labelValues).Add(1)
// Update activity for both directions
                updateActivity(srcIP, dstIP)
                break
            }
        }
    }
}
func isBidirectionalPair(srcIP, dstIP string, pair struct {
    Source      string `json:"source"`
    Destination string `json:"destination"`
}) bool {
    matchForward := matchIPorSubnet(srcIP, pair.Source) && matchIPorSubnet(dstIP, pair.Destination)
    matchBackward := matchIPorSubnet(dstIP, pair.Source) && matchIPorSubnet(srcIP, pair.Destination)
    return matchForward || matchBackward
}

func updateActivity(srcIP, dstIP string) {
    key := srcIP + "-" + dstIP
    activityMutex.Lock()
    ipPairActivities[key] = ipPairActivity{LastActivity: time.Now()}
    activityMutex.Unlock()
}

func cleanupInactiveIPPairs() {
    for {
        time.Sleep(time.Minute) // Frequency of cleanup checks
        now := time.Now()
        activityMutex.Lock()
        for key, activity := range ipPairActivities {
            if now.Sub(activity.LastActivity) > metricsTimeout {
                delete(ipPairActivities, key)
            }
        }
        activityMutex.Unlock()
    }
}

func init() {
    prometheus.MustRegister(bytes)
    prometheus.MustRegister(packets)
}

func main() {
    readConfig()

    handle, err := pcap.OpenLive(config.Device, snapshotLen, promiscuous, timeout)
    if err != nil {
        log.Fatalf("Could not open device %s: %v", config.Device, err)
    }
    defer handle.Close()

    bpfFilter := constructBPF(&config)
    if err := applyBPF(handle, bpfFilter); err != nil {
        log.Fatalf("Could not apply BPF filter: %v", err)
    }

    go capturePackets(handle) // Adjusted to pass the pcap handle

    go cleanupInactiveIPPairs()

    http.Handle("/metrics", promhttp.Handler())
    log.Println("Serving metrics on :9914...")
    log.Fatal(http.ListenAndServe(":9914", nil))
}
func ipInSubnet(ipAddr, cidr string) bool {
    ip := net.ParseIP(ipAddr)
    _, subnet, err := net.ParseCIDR(cidr)
    if err != nil {
        log.Printf("Error parsing CIDR: %v\n", err)
        return false
    }
    return subnet.Contains(ip)
}

func matchIPorSubnet(ipAddr, configIP string) bool {
    if strings.Contains(configIP, "/") {
 // configIP is a subnet
        return ipInSubnet(ipAddr, configIP)
    }
// Assume configIP is a single IP
    return ipAddr == configIP
}
func constructBPF(config *Config) string {
    var filters []string
    for _, pair := range config.IPPairs {
// Example filter: "(src net 192.168.1.0/24 and dst net 192.168.2.0/24) or (src net 192.168.2.0/24 and dst net 192.168.1.0/24)"
        forward := fmt.Sprintf("(src net %s and dst net %s)", pair.Source, pair.Destination)
        backward := fmt.Sprintf("(src net %s and dst net %s)", pair.Destination, pair.Source)
        filters = append(filters, forward, backward)
    }
    return strings.Join(filters, " or ")
}
func applyBPF(handle *pcap.Handle, filter string) error {
    return handle.SetBPFFilter(filter)
}
