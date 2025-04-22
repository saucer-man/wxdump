package model

type Process struct {
	PID         uint32
	ExePath     string
	Version     int
	FullVersion string
	Status      string
	DataDir     string
	Wxid        string
}

const (
	StatusInit    = ""
	StatusOffline = "offline"
	StatusOnline  = "online"
)
