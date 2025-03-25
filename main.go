package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	dockerSocket    = "/var/run/docker.sock"
	exporterVersion = "0.0.2"
)

var dockerClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", dockerSocket)
		},
		DisableKeepAlives: true,
	},
	Timeout: 10 * time.Second,
}

type ContainerStats struct {
	ID         string
	Name       string
	CPUPercent float64
	MemUsage   float64
	MemLimit   float64
	MemPercent float64
	Uptime     float64
}

var (
	cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "docker_container_cpu_usage_percent", Help: "CPU usage of the container"},
		[]string{"container_id", "container_name"},
	)
	memUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "docker_container_memory_usage_bytes", Help: "Memory usage"},
		[]string{"container_id", "container_name"},
	)
	memLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "docker_container_memory_limit_bytes", Help: "Memory limit"},
		[]string{"container_id", "container_name"},
	)
	memPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "docker_container_memory_usage_percent", Help: "Memory usage percent"},
		[]string{"container_id", "container_name"},
	)
	uptime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "docker_container_uptime_seconds", Help: "Container uptime"},
		[]string{"container_id", "container_name"},
	)
)

func getPort() string {
	versionFlag := flag.Bool("version", false, "Print the exporter version and exit")
	portFlag := flag.String("port", "", "Port to run the exporter on")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Docker Exporter version %s\n", exporterVersion)
		os.Exit(0)
	}

	if *portFlag != "" {
		return ":" + *portFlag
	}

	if envPort := os.Getenv("EXPORTER_PORT"); envPort != "" {
		return ":" + envPort
	}

	return ":9102"
}


func getContainers() ([]map[string]interface{}, error) {
	req, err := http.NewRequest("GET", "http://localhost/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := dockerClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var containers []map[string]interface{}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &containers)
	return containers, err
}

func getContainerStats(containerID string) (*ContainerStats, error) {
	statsReq, err := http.NewRequest("GET", fmt.Sprintf("http://localhost/containers/%s/stats?stream=false", containerID), nil)
	if err != nil {
		return nil, err
	}
	statsResp, err := dockerClient.Do(statsReq)
	if err != nil {
		return nil, err
	}
	defer statsResp.Body.Close()

	var stats map[string]interface{}
	body, err := io.ReadAll(statsResp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, err
	}

	cpuDelta := getFloat(stats, "cpu_stats.cpu_usage.total_usage") - getFloat(stats, "precpu_stats.cpu_usage.total_usage")
	systemDelta := getFloat(stats, "cpu_stats.system_cpu_usage") - getFloat(stats, "precpu_stats.system_cpu_usage")
	cpuPercent := 0.0
	if systemDelta > 0 {
		cpuPercent = (cpuDelta / systemDelta) * 100.0
	}

	memUsage := getFloat(stats, "memory_stats.usage")
	memLimit := getFloat(stats, "memory_stats.limit")
	memPercent := (memUsage / memLimit) * 100.0

	infoReq, err := http.NewRequest("GET", fmt.Sprintf("http://localhost/containers/%s/json", containerID), nil)
	if err != nil {
		return nil, err
	}
	infoResp, err := dockerClient.Do(infoReq)
	if err != nil {
		return nil, err
	}
	defer infoResp.Body.Close()

	var info map[string]interface{}
	body, err = io.ReadAll(infoResp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	startTimeStr := info["State"].(map[string]interface{})["StartedAt"].(string)
	startTime, err := time.Parse(time.RFC3339Nano, startTimeStr)
	if err != nil {
		return nil, err
	}
	uptime := time.Since(startTime).Seconds()

	name := strings.TrimPrefix(info["Name"].(string), "/")

	return &ContainerStats{
		ID:         containerID,
		Name:       name,
		CPUPercent: cpuPercent,
		MemUsage:   memUsage,
		MemLimit:   memLimit,
		MemPercent: memPercent,
		Uptime:     uptime,
	}, nil
}

func updateMetrics(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping metrics update...")
			return
		default:
			containers, err := getContainers()
			if err != nil {
				log.Println("Error fetching containers:", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for _, container := range containers {
				containerID := container["Id"].(string)
				stats, err := getContainerStats(containerID)
				if err != nil {
					log.Printf("Error fetching stats for container %s: %v\n", containerID, err)
					continue
				}

				cpuUsage.WithLabelValues(stats.ID, stats.Name).Set(stats.CPUPercent)
				memUsage.WithLabelValues(stats.ID, stats.Name).Set(stats.MemUsage)
				memLimit.WithLabelValues(stats.ID, stats.Name).Set(stats.MemLimit)
				memPercent.WithLabelValues(stats.ID, stats.Name).Set(stats.MemPercent)
				uptime.WithLabelValues(stats.ID, stats.Name).Set(stats.Uptime)
			}

			time.Sleep(5 * time.Second)
		}
	}
}

func getFloat(data map[string]interface{}, path string) float64 {
	parts := strings.Split(path, ".")
	var val interface{} = data
	for _, part := range parts {
		m, ok := val.(map[string]interface{})
		if !ok {
			return 0.0
		}
		val = m[part]
	}
	if f, ok := val.(float64); ok {
		return f
	}
	return 0.0
}

func main() {
	exporterPort := getPort()
	log.Printf("Starting Docker Exporter version %s on port %s...\n", exporterVersion, exporterPort)

	prometheus.MustRegister(cpuUsage, memUsage, memLimit, memPercent, uptime)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go updateMetrics(ctx)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(exporterVersion))
	})

	log.Printf("Exporter running on http://localhost%s/metrics\n", exporterPort)
	if err := http.ListenAndServe(exporterPort, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

