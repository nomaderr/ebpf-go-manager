package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Path to eBPF program and result
const (
	ebpfSource    = "block.c"      // Your eBPF program (source)
	ebpfPackage   = "package.json" // Result of compilation via ecc
	pinnedMapPath = "/sys/fs/bpf/path_block_map"
)

// We map keys to paths (must match enum in eBPF code)
var pathKeys = map[string]uint32{
	"/etc/test": 1,
	"/tmp":      2,
	"/var/log":  3,
}

// runCmd - a convenient function to run external commands.
// Returns (stdout+stderr as string, error).
func runCmd(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// compileEBPF compiles an eBPF program via ecc.
func compileEBPF() error {
	log.Printf("Compiling eBPF program: ecc %s", ebpfSource)
	out, err := runCmd("ecc", ebpfSource)
	if err != nil {
		return fmt.Errorf("Error compiling ecc: %v\nOutput:\n%s", err, out)
	}
	log.Println("Compiled successfully. ecc output:")
	log.Println(out)
	return nil
}

// startEcliRun runs "ecli run package.json" (non-blocking) and returns *exec.Cmd for control.
func startEcliRun() (*exec.Cmd, error) {
	log.Printf("Starting ecli run %s\n", ebpfPackage)
	cmd := exec.Command("ecli", "run", ebpfPackage)
	// To see ecli output in console, redirect stdout/stderr
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("Failed to start ecli: %v", err)
	}
	// Return cmd so we can kill on exit
	return cmd, nil
}

// watchTracePipe reads /sys/kernel/debug/tracing/trace_pipe and prints everything that appears there.
func watchTracePipe(stopCh chan struct{}) {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Printf("Can't open trace_pipe: %v\n", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("[trace_pipe] %s\n", line)
		select {
		case <-stopCh:
			return
		default:
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading trace_pipe: %v\n", err)
	}
}

// findPathBlockMapID searches the output of "bpftool map show" for a map named "path_block_map" and returns its id.
func findPathBlockMapID() (int, error) {
	out, err := runCmd("bpftool", "map", "show")
	if err != nil {
		return 0, fmt.Errorf("bpftool map show error: %v\nOutput:\n%s", err, out)
	}
	// Example of the search string: "2: hash name path_block_map flags 0x0"
	re := regexp.MustCompile(`(?m)^(\d+):\s+hash\s+name\s+path_block_map\b`)
	match := re.FindStringSubmatch(out)
	if match == nil {
		return 0, fmt.Errorf("path_block_map not found in bpftool map show")
	}
	idStr := match[1]
	idInt, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, fmt.Errorf("Error parsing map ID: %v", err)
	}
	return idInt, nil
}

// pinPathBlockMap pins the map path_block_map (with the specified id) to pinnedMapPath.
func pinPathBlockMap(id int) error {
	log.Printf("Pin map path_block_map (id=%d) in %s\n", id, pinnedMapPath)
	out, err := runCmd("bpftool", "map", "pin", "id", fmt.Sprintf("%d", id), pinnedMapPath)
	if err != nil {
		return fmt.Errorf("Pin map error: %v\nOutput:\n%s", err, out)
	}
	return nil
}

// updateMapValue updates (key -> value) in path_block_map
// value=1 => block, value=0 => unblock.
func updateMapValue(key, val uint32) error {
	// Convert key/val to 4 bytes, LE
	kb := []byte{byte(key), 0, 0, 0}
	vb := []byte{byte(val), 0, 0, 0}

	// Collect arguments for bpftool
	args := []string{"map", "update", "pinned", pinnedMapPath, "key"}
	for _, b := range kb {
		args = append(args, fmt.Sprintf("%02x", b))
	}
	args = append(args, "value")
	for _, b := range vb {
		args = append(args, fmt.Sprintf("%02x", b))
	}

	out, err := runCmd("bpftool", args...)
	if err != nil {
		return fmt.Errorf("Error updating map (key=%d, val=%d): %v\nbpftool out:\n%s", key, val, err, out)
	}
	return nil
}

// dumpMap prints the current contents of path_block_map
func dumpMap() {
	out, err := runCmd("bpftool", "map", "dump", "pinned", pinnedMapPath)
	if err != nil {
		log.Printf("Error dumping map: %v\nOutput:\n%s", err, out)
		return
	}
	log.Printf("Current map contents:\n%s", out)
}

// interactiveMenu provides a simple text menu in the console,
// allowing you to enable/disable blocking for different paths and view the contents of the map.
func interactiveMenu() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println()
		fmt.Println("Select action:")
		fmt.Println("1) Lock /etc/test")
		fmt.Println("2) Unlock /etc/test")
		fmt.Println("3) Lock /tmp")
		fmt.Println("4) Unlock /tmp")
		fmt.Println("5) Lock /var/log")
		fmt.Println("6) Unlock /var/log")
		fmt.Println("d) View card contents (dump)")
		fmt.Println("q) Exit")

		fmt.Print("Your choice: ")
		if !scanner.Scan() {
			fmt.Println("Finishing (EOF).")
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		var err error

		switch choice {
		case "1":
			err = updateMapValue(pathKeys["/etc/test"], 1)
			if err != nil {
				log.Println("Error:", err)
			} else {
				fmt.Println("/etc/test: Locking enabled")
			}
		case "2":
			err = updateMapValue(pathKeys["/etc/test"], 0)
			if err != nil {
				log.Println("Error:", err)
			} else {
				fmt.Println("/etc/test: Locking is disabled")
			}
		case "3":
			err = updateMapValue(pathKeys["/tmp"], 1)
			if err != nil {
				log.Println("Error:", err)
			} else {
				fmt.Println("/tmp: Locking is enabled")
			}
		case "4":
			err = updateMapValue(pathKeys["/tmp"], 0)
			if err != nil {
				log.Println("Error:", err)
			} else {
				fmt.Println("/tmp: Locking is disabled")
			}
		case "5":
			err = updateMapValue(pathKeys["/var/log"], 1)
			if err != nil {
				log.Println("Error:", err)
			} else {
				fmt.Println("/var/log: Locking enabled")
			}
		case "6":
			err = updateMapValue(pathKeys["/var/log"], 0)
			if err != nil {
				log.Println("Error:", err)
			} else {
				fmt.Println("/var/log: Locking disabled")
			}
		case "d":
			dumpMap()
		case "q", "quit", "exit":
			fmt.Println("Exiting the menu.")
			return
		default:
			fmt.Println("Unknown command:", choice)
		}
	}
}

func main() {
	// 1) Compile eBPF (if necessary)
	if err := compileEBPF(); err != nil {
		log.Fatalln(err)
	}

	// 2) Run ecli run package.json
	cmd, err := startEcliRun()
	if err != nil {
		log.Fatalln(err)
	}

	// 3) In a separate goroutine, read trace_pipe
	stopTrace := make(chan struct{})
	go watchTracePipe(stopTrace)

	// A short pause so that the eBPF program has time to load
	time.Sleep(2 * time.Second)

	// 4) Find the path_block_map in bpftool and pin it.
	mapID, err := findPathBlockMapID()
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	if err := pinPathBlockMap(mapID); err != nil {
		log.Fatalf("Error pinning map: %v\n", err)
	}
	log.Printf("Map path_block_map (id=%d) successfully pinned\n", mapID)

	// 5) Go to the "interactive menu"
	interactiveMenu()

	// Finish work: stop reading trace_pipe and ecli
	close(stopTrace)
	if cmd.Process != nil {
		log.Println("Stopping ecli...")
		_ = cmd.Process.Kill()
	}

	log.Println("Program terminated.")
}
