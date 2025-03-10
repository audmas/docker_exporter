package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const dockerAPI = "http://localhost:2375"
const exporterPort = ":9102" // Changed default port to 9102

// ContainerStats holds the stats we fetch from the Docker API
type ContainerStats struct {
	ID         string
	Name       string
	CPUPercent float64
	MemUsage   float64
	MemLimit   float64
	MemPercent float64
	Uptime     float64 // Uptime in seconds
}

// Metrics for Prometheus
var (
	cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "docker_container_cpu_usage_percent",
			Help: "CPU usage of the container as a percentage",
		},
		[]string{"container_id", "container_name"},
	)

	memUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "docker_container_memory_usage_bytes",
			Help: "Memory usage of the container in bytes",
		},
		[]string{"container_id", "container_name"},
	)

	memLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "docker_container_memory_limit_bytes",
			Help: "Memory limit of the container in bytes",
		},
		[]string{"container_id", "container_name"},
	)

	memPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "docker_container_memory_usage_percent",
			Help: "Memory usage percentage of the container",
		},
		[]string{"container_id", "container_name"},
	)

	uptime = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "docker_container_uptime_seconds",
			Help: "Uptime of the container in seconds",
		},
		[]string{"container_id", "container_name"},
	)
)

// Fetch running containers
func getContainers() ([]map[string]interface{}, error) {
	resp, err := http.Get(dockerAPI + "/containers/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var containers []map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &containers)
	if err != nil {
		return nil, err
	}

	return containers, nil
}

// Fetch container stats
func getContainerStats(containerID string) (*ContainerStats, error) {
	resp, err := http.Get(dockerAPI + "/containers/" + containerID + "/stats?stream=false")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &stats)
	if err != nil {
		return nil, err
	}

	// Extract CPU usage
	cpuDelta := stats["cpu_stats"].(map[string]interface{})["cpu_usage"].(map[string]interface{})["total_usage"].(float64) -
		stats["precpu_stats"].(map[string]interface{})["cpu_usage"].(map[string]interface{})["total_usage"].(float64)
	systemDelta := stats["cpu_stats"].(map[string]interface{})["system_cpu_usage"].(float64) -
		stats["precpu_stats"].(map[string]interface{})["system_cpu_usage"].(float64)
	cpuPercent := 0.0
	if systemDelta > 0.0 {
		cpuPercent = (cpuDelta / systemDelta) * 100.0
	}

	// Extract memory usage
	memUsage := stats["memory_stats"].(map[string]interface{})["usage"].(float64)
	memLimit := stats["memory_stats"].(map[string]interface{})["limit"].(float64)
	memPercent := (memUsage / memLimit) * 100.0

	// Fetch container start time
	resp, err = http.Get(dockerAPI + "/containers/" + containerID + "/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var containerInfo map[string]interface{}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &containerInfo)
	if err != nil {
		return nil, err
	}

	startTimeStr := containerInfo["State"].(map[string]interface{})["StartedAt"].(string)
	startTime, err := time.Parse(time.RFC3339Nano, startTimeStr)
	if err != nil {
		return nil, err
	}

	uptimeSeconds := time.Since(startTime).Seconds()

	// Get container name
	name := containerInfo["Name"].(string)
	name = strings.TrimPrefix(name, "/") // Remove leading '/'

	return &ContainerStats{
		ID:         containerID,
		Name:       name,
		CPUPercent: cpuPercent,
		MemUsage:   memUsage,
		MemLimit:   memLimit,
		MemPercent: memPercent,
		Uptime:     uptimeSeconds,
	}, nil
}

// Collect and update metrics
func updateMetrics() {
	for {
		containers, err := getContainers()
		if err != nil {
			fmt.Println("Error fetching containers:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, container := range containers {
			containerID := container["Id"].(string)
			stats, err := getContainerStats(containerID)
			if err != nil {
				fmt.Println("Error fetching stats for container", containerID, ":", err)
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

func main() {
	// Register Prometheus metrics
	prometheus.MustRegister(cpuUsage, memUsage, memLimit, memPercent, uptime)

	// Start updating metrics in the background
	go updateMetrics()

	// Start HTTP server for Prometheus scraping
	http.Handle("/metrics", promhttp.Handler())
	fmt.Println("Docker Stats Exporter running on http://localhost" + exporterPort + "/metrics")
	http.ListenAndServe(exporterPort, nil)
}
