package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "LapseZeroAgent"

var dataDir = filepath.Join(os.Getenv("ProgramData"), "LapseZero Agent")
var defaultConfigPath = filepath.Join(dataDir, "config.json")
var defaultStateDir = filepath.Join(dataDir, "state")
var installedExe = filepath.Join(os.Getenv("ProgramFiles"), "LapseZero Agent", "lapsezero-agent.exe")

func platformCommand(command string, args []string) bool {
	switch command {
	case "install":
		if err := installWindows(args); err != nil {
			log.Fatal(err)
		}
		return true
	case "update":
		log.Fatal("automatic updates are unsupported on Windows; download the release exe and run install to upgrade")
	}
	return false
}

func cmdRun(args []string) {
	if len(args) != 0 {
		log.Fatal("Windows run uses the installed config and state directory; no arguments are supported")
	}
	service, err := svc.IsWindowsService()
	if err != nil {
		log.Fatal(err)
	}
	if service {
		if err := svc.Run(serviceName, windowsService{}); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runWindows(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func runWindows(ctx context.Context) error {
	if err := os.MkdirAll(defaultStateDir, 0700); err != nil {
		return err
	}
	unlock, err := lockInstance(filepath.Join(dataDir, "agent.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := loadConfig(defaultConfigPath)
	if err != nil {
		return err
	}
	if err := initHTTPConfig(); err != nil {
		return err
	}
	defer httpTerminate.Call(2, 0)
	c := newClient(cfg.Server, cfg.Credential)
	c.ctx = ctx
	a := agent{client: c, journal: journalStore{path: filepath.Join(defaultStateDir, "journal.json")}, info: hostInfo()}
	log.Printf("lapsezero-agent %s started, server %s", version, cfg.Server)
	return a.run()
}

func lockInstance(path string) (func(), error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return nil, errors.New("another lapsezero-agent instance is already running")
	}
	if err != nil {
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}

type eventWriter struct{ log *eventlog.Log }

func (w eventWriter) Write(p []byte) (int, error) {
	if err := w.log.Info(1, string(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

type windowsService struct{}

func (windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ev, err := eventlog.Open(serviceName)
	if err != nil {
		return false, 1
	}
	defer ev.Close()
	log.SetOutput(eventWriter{ev})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runWindows(ctx) }()
	state := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- state
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			var apiErr *apiError
			if err == nil || errors.Is(err, context.Canceled) || errors.As(err, &apiErr) && apiErr.Code == codeCredentialInvalid {
				return false, 0
			}
			ev.Error(1, err.Error())
			return false, 1
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- state
			case svc.Stop, svc.Shutdown:
				state = svc.Status{State: svc.StopPending, WaitHint: 30000}
				changes <- state
				cancel()
			}
		case <-ticker.C:
			if state.State == svc.StopPending {
				state.CheckPoint++
				changes <- state
			}
		}
	}
}

func stopService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("service did not stop within two minutes")
}

func installWindows(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fs.String("server", "", "LapseZero site URL")
	token := fs.String("token", "", "one-time enrollment token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.EqualFold(source, installedExe) {
		return errors.New("download the release exe to a temporary directory before running install")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	existing := err == nil
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	if existing {
		defer s.Close()
		if err := stopService(s); err != nil {
			return err
		}
	} else if *server == "" || *token == "" {
		return errors.New("install requires --server and --token")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dataDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	if err := os.MkdirAll(defaultStateDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(installedExe), 0755); err != nil {
		return err
	}
	if err := copyFile(source, installedExe); err != nil {
		return err
	}
	if !existing {
		credential, err := newClient(*server, "").enroll(*token, hostInfo())
		if err != nil {
			return err
		}
		if err := saveConfig(defaultConfigPath, config{Server: *server, Credential: credential}); err != nil {
			return err
		}
		s, err = m.CreateService(serviceName, installedExe, mgr.Config{DisplayName: "LapseZero Agent", StartType: mgr.StartAutomatic}, "run")
		if err != nil {
			return err
		}
		defer s.Close()
		if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Info|eventlog.Warning|eventlog.Error); err != nil {
			return err
		}
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 30 * time.Second}}, 86400); err != nil {
		return err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Println("LapseZero Agent service started")
	return nil
}

func cmdUninstall() {
	if err := uninstallWindows(); err != nil {
		log.Fatal(err)
	}
}
func uninstallWindows() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		if err := stopService(s); err != nil {
			return err
		}
		if err := s.Delete(); err != nil {
			return err
		}
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	if err := os.RemoveAll(dataDir); err != nil {
		return err
	}
	if err := eventlog.Remove(serviceName); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	fmt.Printf("Service and data removed. Delete the executable with: Remove-Item -LiteralPath '%s'\n", installedExe)
	return nil
}
