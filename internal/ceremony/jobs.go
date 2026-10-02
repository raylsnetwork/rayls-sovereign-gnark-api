package ceremony

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// bytesPerJob is the peak memory one circuit needs, measured on the 2^17
// circuits with some headroom.
const bytesPerJob = 2_500_000_000

// maxAutoJobs caps the automatic choice; beyond this, jobs mostly compete for
// memory bandwidth.
const maxAutoJobs = 9

// AutoJobs picks how many circuits to process in parallel: half the CPUs (each
// job already uses about two cores), limited by available memory, at least 1.
func AutoJobs() int {
	jobs := min(runtime.NumCPU()/2, maxAutoJobs)
	if avail := availableMemory(); avail > 0 {
		jobs = min(jobs, int(avail/bytesPerJob))
	}
	return max(jobs, 1)
}

// availableMemory returns MemAvailable from /proc/meminfo in bytes, or 0 where
// that is not available (e.g. macOS).
func availableMemory() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "MemAvailable:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb * 1024
		}
	}
	return 0
}
