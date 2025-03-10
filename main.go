package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	dockerSocket = "/var/run/docker.sock"
	exporterPort = ":9102"
)

// ContainerStats stores container stats
type ContainerStats struct {
	ID         string
	Name       string
	CPUPercent float64
	MemUsage   float64
	MemLimit   float64
	MemPercent float64
	Uptime     float64
}

// Prometheus metrics
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

// getDockerClient returns an HTTP client that connects via Unix socket
func getDockerClient() (*http.Client, error) {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", dockerSocket)
		},
	}
	client := &http.Client{Transport: transport}
	return client, nil
}

// getContainers fetches running containers
func getContainers() ([]map[string]interface{}, error) {
	client, err := getDockerClient()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", "http://localhost/containers/json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
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

// getContainerStats fetches stats for a container
func getContainerStats(containerID string) (*ContainerStats, error) {
	client, err := getDockerClient()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", "http://localhost/containers/"+containerID+"/stats?stream=false", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
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
	req, err = http.NewRequest("GET", "http://localhost/containers/"+containerID+"/json", nil)
	if err != nil {
		return nil, err
	}

	resp, err = client.Do(req)
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
	name = strings.TrimPrefix(name, "/")

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

// updateMetrics collects and updates container metrics
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
	prometheus.MustRegister(cpuUsage, memUsage, memLimit, memPercent, uptime)
	go updateMetrics()
	http.Handle("/metrics", promhttp.Handler())
	fmt.Println("Docker Stats Exporter running on http://localhost" + exporterPort + "/metrics")
	http.ListenAndServe(exporterPort, nil)
}
