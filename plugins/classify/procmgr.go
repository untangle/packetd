// Package classify classifies sessions as certain applications
// each packet gets sent to a classd daemon (the categorization engine)
// the classd daemon returns the classification information and classify
// attaches the information to the session.
package classify

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/untangle/packetd/services/logger"
)

const daemonBinary = "/usr/bin/classd"

var daemonProcess *exec.Cmd
var daemonWaiter sync.WaitGroup
var shutdownFlag int32

// daemonProcessManager is a goroutine to start and monitor the untnagle-classd daemon
func daemonProcessManager() {

	// send the initial signal to launch the daemon
	signalProcessManager(daemonStartup)

	for {
		message := <-processChannel

		// +++ systemShutdown is called from PluginShutdown. We set the shutdown flag and then
		// signal the running daemon to terminate. When the
		if message == systemShutdown {
			atomic.StoreInt32(&shutdownFlag, 1)
			daemonProcessShutdown()
		}

		// +++ daemonStartup is sent during system startup and after the daemon has stopped unexpectedly
		// and needs to be restarted. We launch the daemon process which will also create goroutines to
		// capture stdout and stderr, and we call daemonWaiter.Add(1) for each of them. After the daemon
		// has started we signal for the initial socket connect.
		if message == daemonStartup {
			daemonProcessStartup()
			signalSocketManager(socketConnect)

			// We use a goroutine to wait for the process to finish. First we wait for daemonWaiter
			// which will return when the stdout and stderr writers have finished. Then we call
			// proc.Wait() which should return immediately. Waiting for daemonWaiter first ensures
			// we don't touch daemonProcess while the writers are active which would cause a data race.
			go func(proc *exec.Cmd) {
				daemonWaiter.Wait()

				err := proc.Wait()
				if err != nil {
					logger.Info("The classd daemon has failed. Error:%v\n", err)
				} else {
					logger.Info("The classd daemon has exited.\n")
				}

				// If the shutdown flag is clear the daemon needs to be restarted, otherwise the
				// system is shutting down. In both cases we put signal via the channel to prevent
				// a data race between this exec monitor goroutine and the main daemon manager.
				if atomic.LoadInt32(&shutdownFlag) == 0 {
					signalProcessManager(daemonShutdown)
					signalProcessManager(daemonStartup)
				} else {
					signalProcessManager(daemonShutdown)
					signalProcessManager(daemonFinished)
				}
			}(daemonProcess)
		}
		// +++ daemonShutdown is sent from inside the exec wait goroutine to cleanup after
		// the daemon has died or we when we have received a system shutdown message
		if message == daemonShutdown {
			daemonProcessShutdown()
		}

		// +++ daemonFinished is sent after the daemon process terminates in response
		// to a system shutdown message letting us know to to exit
		if message == daemonFinished {
			logger.Info("The daemonProcessManager is finished\n")
			shutdownChannel <- true
			return
		}

	} // end of main for loop
}

// starts the daemon and uses a goroutine to wait for it to finish
func daemonProcessStartup() {
	var err error
	var daemonStdout io.ReadCloser
	var daemonStderr io.ReadCloser

	// start the classd daemon with the mfw flag to enable our mode of operation
	// include the local flag so we can capture the log output
	// include the memory watchdog flag to set the size limit
	// include the debug flag when our own debug mode is enabled
	if logger.IsDebugEnabled() {
		daemonProcess = exec.Command(daemonBinary, "-mfw", "-l", "-w32768", "-d")
	} else {
		daemonProcess = exec.Command(daemonBinary, "-mfw", "-l", "-w32768")
	}

	// set a different process group so it doesn't get packetd signals
	daemonProcess.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// not sure why we do this since we don't actually save or use the pipe
	_, err = daemonProcess.StdinPipe()
	if err != nil {
		logger.Err("Error %v getting daemon stdin pipe\n", err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}

	// get a pipe to the process stderr so we can grab the output and send to the logger
	daemonStderr, err = daemonProcess.StderrPipe()
	if err != nil {
		logger.Err("Error %v getting daemon stderr pipe\n", err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}

	// get a pipe to the process stdout so we can grab the output and send to the logger
	daemonStdout, err = daemonProcess.StdoutPipe()
	if err != nil {
		logger.Err("Error %v getting daemon stdout pipe\n", err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}

	// call the start function, check for error, and cleanup if things go bad
	err = daemonProcess.Start()
	if err != nil {
		logger.Err("Error starting classify daemon %s (%v)\n", daemonBinary, err)
		daemonProcess.Process.Release()
		daemonProcess = nil
		return
	}

	// Wait for startup to complete
	scanner := bufio.NewScanner(daemonStdout)
	for scanner.Scan() {
		// look for "starting" message
		txt := scanner.Text()
		logger.Info("classd: %v\n", txt)
		if strings.Contains(txt, "netserver thread is starting") {
			break
		}
	}

	daemonWaiter.Add(2)
	go daemonOutputWriter("stdout", daemonStdout)
	go daemonOutputWriter("stderr", daemonStderr)

	logger.Info("The classd daemon has been started. PID:%d\n", daemonProcess.Process.Pid)
}

// called to send SIGINT to the classify daemon which will cause normal shutdown
func daemonProcessShutdown() {
	if daemonProcess == nil {
		return
	}

	// signal an interrupt signal to the daemon
	err := daemonProcess.Process.Signal(os.Interrupt)
	if err != nil {
		if !strings.Contains(err.Error(), "process already finished") {
			logger.Err("Error stopping classd daemon: %v\n", err)
		}
	} else {
		logger.Info("The classd daemon has been stopped\n")
	}

	daemonProcess = nil
}

// daemonOutputWriter just writes any output from the daemon to stdout
func daemonOutputWriter(name string, reader io.ReadCloser) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		logger.Info("classd: %v\n", scanner.Text())
	}
	logger.Info("The daemonOutputWriter(%s) is finished\n", name)
	daemonWaiter.Done()
}
