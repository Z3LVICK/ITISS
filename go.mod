//go:build linux
// +build linux

package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"os"
	"os/exec"
)

const (
	maxRounds       = 500
	maxProbeTries   = 500
	maxFDToInspect  = 500
	maxCaptureBytes = 8 * 1024 * 1024
)

func main() {
	targetBin, targetArgs, capturePath, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	for round := 0; round < maxRounds; round++ {
		hit, probeTry, pid, err := runRound(targetBin, targetArgs, capturePath)
		if err != nil {
			log.Printf("round=%d error=%v", round, err)
			continue
		}
		if hit {
			log.Printf("race-condition-hit-at probeTry=%d round=%d pid=%d", probeTry, round, pid)
			return
		}
	}

	log.Printf("no hit after %d rounds", maxRounds)
}

func parseArgs(argv []string) (targetBin string, targetArgs []string, capturePath string, err error) {
	if len(argv) < 2 {
		return "", nil, "", fmt.Errorf("usage: %s <bin> [arg1 arg2 ...] [optional_file_to_capture]", argv[0])
	}

	targetBin = argv[1]
	if len(argv) == 2 {
		return targetBin, nil, "", nil
	}

	targetArgs = append(targetArgs, argv[2:]...)
	capturePath = targetArgs[len(targetArgs)-1]
	targetArgs = targetArgs[:len(targetArgs)-1]

	return targetBin, targetArgs, capturePath, nil
}

func runRound(targetBin string, targetArgs []string, capturePath string) (hit bool, probeTry int, pid int, err error) {
	cmd := exec.Command(targetBin, targetArgs...)

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return false, 0, 0, err
	}
	defer devNull.Close()

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	if err := cmd.Start(); err != nil {
		return false, 0, 0, err
	}
	defer cmd.Wait()

	pid = cmd.Process.Pid

	pidFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false, 0, pid, err
	}
	defer unix.Close(pidFD)

	return probeTarget(pidFD, capturePath, pid)
}

func probeTarget(pidFD int, capturePath string, pid int) (hit bool, probeTry int, outPID int, err error) {
	var capturedFDs []int
	outPID = pid

	for probeTry = 0; probeTry < maxProbeTries && !hit; probeTry++ {
		for fd := 3; fd < maxFDToInspect; fd++ {
			dupFD, dupErr := unix.PidfdGetfd(pidFD, fd, 0)
			if dupErr != nil {
				continue
			}

			capturedFDs = append(capturedFDs, dupFD)
			hit = true
		}
	}

	if !hit {
		return false, probeTry, outPID, nil
	}

	inspectCapturedFDs(capturedFDs, capturePath)
	return true, probeTry, outPID, nil
}

func inspectCapturedFDs(fds []int, capturePath string) {
	for _, fd := range fds {
		link := fmt.Sprintf("/proc/self/fd/%d", fd)
		path, err := os.Readlink(link)
		if err != nil {
			unix.Close(fd)
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			log.Printf("stat error path=%s err=%v", path, err)
			unix.Close(fd)
			continue
		}

		log.Printf("file captured: %s", path)
		log.Printf("permissions: %s", info.Mode().Perm())
		log.Printf("full mode: %s", info.Mode())

		if capturePath != "" && path == capturePath {
			logCapturedContent(fd, path)
		}

		unix.Close(fd)
	}
}

func logCapturedContent(fd int, path string) {
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		log.Printf("seek error path=%s err=%v", path, err)
		return
	}

	buffer := make([]byte, maxCaptureBytes)
	n, err := unix.Read(fd, buffer)
	if err != nil {
		log.Printf("read error path=%s err=%v", path, err)
		return
	}
	if n <= 0 {
		return
	}

	log.Printf("file content captured path=%s bytes=%d", path, n)
	log.Println("******")
	log.Println(string(buffer[:n]))
	log.Println("******")
}
