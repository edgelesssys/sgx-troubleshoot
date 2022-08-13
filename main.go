package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/klauspost/cpuid"
)

var (
	timestamp = "0"
	verbose   = flag.Bool("v", false, "verbose output")
)

func main() {
	fmt.Print("SGX troubleshooter by Edgeless Systems (build timestamp: ", timestamp, ")\n\n")

	testAll := flag.Bool("test-all", false, "run all extended tests")
	testEnclave := flag.Bool("test-enclave", false, "run the SGX test enclave")
	testDocker := flag.Bool("test-docker", false, "run the SGX test enclave in a Docker container")
	testPCCS := flag.Bool("test-pccs", false, "test connection to the configured PCCS")
	flag.Parse()
	if *testAll {
		*testEnclave = true
		*testDocker = true
		*testPCCS = true
	}

	info := newSystemInfo()

	if *verbose {
		fmt.Println()
		runWithOutput(exec.Command("lscpu"))
		runWithOutput(exec.Command("sh", "-c", "dmesg | grep microcode"))
		runWithOutput(exec.Command("sh", "-c", "lsmod | grep -i sgx"))
		runWithOutput(exec.Command("sh", "-c", "dmesg | grep -i sgx"))
		runWithOutput(exec.Command("service", "aesmd", "status"))
		runWithOutput(exec.Command("sh", "-c", "apt list --installed | grep -e sgx -e dcap"))
	}

	var encDbg, encProd, dockerDbg, dockerProd runResult
	if *testEnclave {
		encDbg = runEnclave(testappDebugEnclave)
		encProd = runEnclave(testappProductionEnclave)
	}
	if *testDocker {
		dockerDbg = runDocker("enclave_debug.signed")
		dockerProd = runDocker("enclave.signed")
	}

	pccsConnection := "not tested"
	if *testPCCS {
		if info.pccsURL == "" {
			pccsConnection = "URL not set"
		} else {
			url := info.pccsURL + "rootcacrl"
			resp, err := http.Get(url)
			if err == nil {
				resp.Body.Close()
				pccsConnection = resp.Status
			} else {
				client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
				if resp, err := client.Get(url); err == nil {
					resp.Body.Close()
					pccsConnection = resp.Status + " (certificate verification failure has been ignored)"
				} else {
					pccsConnection = err.Error()
				}
			}
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	writeRow(tw, "CPU name", info.cpuName)
	writeRow(tw, "CPU supports SGX", info.hasSGX)
	writeRow(tw, "CPU supports SGX-FLC", info.hasFLC)
	writeRow(tw, "SGX enabled in BIOS/Hypervisor", info.sgxEnabled)
	writeRow(tw, "SGX2", info.sgx2)
	writeRow(tw, "EPC size MiB", info.epc)
	writeRow(tw, "SMT/Hyper-threading", info.smt)
	writeRow(tw, "uname", info.uname)
	writeRow(tw, "Cloud", info.cloud)
	writeRow(tw, "/dev mount options", strings.Join(info.devMountOpts, ","))
	writeRow(tw, "Current user", info.user)
	writeRow(tw, "Users of group sgx_prv", strings.Join(info.sgxPrv, " "))
	writeRow(tw, "AESM status", info.aesmStatus)
	writeRow(tw, "AESM socket", info.aesmSocket)
	writeRow(tw, "Value of SGX_AESM_ADDR", info.aesmAddr)
	writeRow(tw, "PCCS URL", info.pccsURL)
	writeRow(tw, "PCCS use secure cert", info.useSecureCert)
	writeRow(tw, "PCSS API version", info.pccsAPIVersion)
	writeRow(tw, "PCCS connection", pccsConnection)
	writeDMI(tw, "sys_vendor")
	writeDMI(tw, "board_vendor")
	writeDMI(tw, "board_name")
	writeDMI(tw, "board_version")
	writeDMI(tw, "bios_vendor")
	writeDMI(tw, "bios_version")
	writeDMI(tw, "bios_date")
	writeDMI(tw, "bios_release")
	writeDev(tw, "")
	writeDev(tw, "sgx")
	writeDev(tw, "sgx_enclave")
	writeDev(tw, "sgx/enclave")
	writeDev(tw, "sgx_provision")
	writeDev(tw, "sgx/provision")
	writeDev(tw, "isgx")
	if *testEnclave {
		encDbg.write(tw, "Debug enclave")
		encProd.write(tw, "Production enclave")
	}
	if *testDocker {
		dockerDbg.write(tw, "Debug Docker enclave")
		dockerProd.write(tw, "Production Docker enclave")
	}
	tw.Flush()
	fmt.Println()

	fmt.Println("Quote providers:")
	var found bool
	err := filepath.WalkDir("/usr/lib", func(path string, dir fs.DirEntry, err error) error {
		if !strings.Contains(path, "quoteprov") {
			return nil
		}
		found = true
		if evalPath, err := filepath.EvalSymlinks(path); err != nil {
			fmt.Println(path, "=>", err)
		} else if evalPath == path {
			fmt.Println(path)
		} else {
			fmt.Println(path, "=>", evalPath)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	} else if !found {
		fmt.Println("none found")
	}
	fmt.Println()

	if len(os.Args) < 2 {
		fmt.Println("For full diagnostics, run:", os.Args[0], "-v -test-all")
	}
}

func writeRow(wr io.Writer, col1 string, col2 interface{}) {
	fmt.Fprint(wr, col1, "\t", col2, "\n")
}

func writeDMI(wr io.Writer, id string) {
	val, err := os.ReadFile("/sys/devices/virtual/dmi/id/" + id)
	if err != nil {
		writeRow(wr, id, err)
		return
	}
	writeRow(wr, id, string(bytes.TrimSpace(val)))
}

func writeDev(wr io.Writer, path string) {
	path = filepath.Join("/dev", path)
	info, err := os.Lstat(path)
	if err != nil {
		writeRow(wr, path, err)
		return
	}
	mode := info.Mode()
	modeStr := mode.String()
	if mode&os.ModeSymlink != 0 {
		modeStr += " "
		if link, err := os.Readlink(path); err != nil {
			modeStr += err.Error()
		} else {
			modeStr += link
		}
	}
	writeRow(wr, path, modeStr)
}

func printVerboseError(format string, args ...interface{}) {
	if *verbose {
		fmt.Printf("ERROR: "+format+"\n", args...)
	}
}

func runWithOutput(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	fmt.Println(strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		fmt.Println(err)
	}
	fmt.Println()
}

func getUsersOfGroup(group string) ([]string, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) == 4 && fields[0] == group {
			return strings.Split(fields[3], ","), nil
		}
	}

	return nil, scanner.Err()
}

func getMountOpts(target string) ([]string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) == 6 && fields[1] == target {
			return strings.Split(fields[3], ","), nil
		}
	}

	return nil, scanner.Err()
}

type systemInfo struct {
	cpuName        string
	hasSGX         bool
	hasFLC         bool
	sgxEnabled     bool
	sgx2           bool
	epc            uint64
	smt            string
	uname          string
	cloud          string
	devMountOpts   []string
	user           string
	sgxPrv         []string
	aesmStatus     string
	aesmSocket     os.FileMode
	aesmAddr       string
	pccsURL        string
	useSecureCert  string
	pccsAPIVersion string
}

func newSystemInfo() systemInfo {
	sgx := cpuid.CPU.SGX

	info := systemInfo{
		cpuName:    cpuid.CPU.BrandName,
		hasSGX:     sgx.Available,
		hasFLC:     sgx.LaunchControl,
		sgxEnabled: sgx.SGX1Supported,
		sgx2:       sgx.SGX2Supported,
		epc:        sgx.EPCSections[0].EPCSize / 1024 / 1024,
	}

	if smt, err := os.ReadFile("/sys/devices/system/cpu/smt/active"); err != nil {
		info.smt = err.Error()
	} else {
		switch string(smt[0]) {
		case "0":
			info.smt = fmt.Sprint(false)
		case "1":
			info.smt = fmt.Sprint(true)
		}
	}

	if out, err := exec.Command("uname", "-a").Output(); err != nil {
		info.uname = err.Error()
	} else {
		info.uname = string(bytes.TrimSpace(out))
	}

	if val, err := os.ReadFile("/sys/devices/virtual/dmi/id/chassis_asset_tag"); err != nil {
		printVerboseError("chassis_asset_tag: %v", err)
	} else if string(bytes.TrimSpace(val)) == "7783-7084-3265-9085-8269-3286-77" {
		info.cloud = "Azure"
	}

	if opts, err := getMountOpts("/dev"); err != nil {
		printVerboseError("/dev: %v", err)
	} else {
		info.devMountOpts = opts
	}

	if usr, err := user.Current(); err != nil {
		info.user = err.Error()
	} else {
		info.user = usr.Username
	}

	if users, err := getUsersOfGroup("sgx_prv"); err != nil {
		printVerboseError("sgx_prv: %v", err)
	} else {
		info.sgxPrv = users
	}

	if out, err := exec.Command("systemctl", "is-active", "aesmd").Output(); err != nil {
		info.aesmStatus = err.Error()
	} else {
		info.aesmStatus = string(bytes.TrimSpace(out))
	}
	if st, err := os.Stat("/var/run/aesmd/aesm.socket"); err != nil {
		printVerboseError("aesm: %v", err)
	} else {
		info.aesmSocket = st.Mode()
	}

	if val, ok := os.LookupEnv("SGX_AESM_ADDR"); !ok {
		info.aesmAddr = "(not set)"
	} else if val == "" {
		info.aesmAddr = "(set, but empty)"
	} else {
		info.aesmAddr = val
	}

	if conf, err := newQcnlConf(); err != nil {
		printVerboseError("sgx_default_qcnl.conf: %v", err)
	} else {
		info.pccsURL = conf.PCCSURL
		if conf.UseSecureCert != nil {
			info.useSecureCert = fmt.Sprint(*conf.UseSecureCert)
		}
		info.pccsAPIVersion = conf.PCCSAPIVersion
	}

	return info
}

type qcnlConf struct {
	PCCSURL        string `json:"pccs_url"`
	UseSecureCert  *bool  `json:"use_secure_cert"`
	PCCSAPIVersion string `json:"pccs_api_version"`
}

func newQcnlConf() (qcnlConf, error) {
	const path = "/etc/sgx_default_qcnl.conf"

	bytes, err := os.ReadFile(path)
	if err != nil {
		return qcnlConf{}, err
	}

	if *verbose {
		fmt.Printf("%v\n%s", path, bytes)
	}

	var result qcnlConf
	if err := json.Unmarshal(regexp.MustCompile(`\s//.*`).ReplaceAllLiteral(bytes, nil), &result); err != nil {
		return qcnlConf{}, err
	}
	return result, nil
}

const (
	ecGetLocalReport     = 2
	ecVerifyLocalReport  = 4
	ecGetRemoteReport    = 8
	ecVerifyRemoteReport = 16
	ecMax                = ecGetLocalReport | ecVerifyLocalReport | ecGetRemoteReport | ecVerifyRemoteReport
)

type runResult struct {
	exitCode     int
	cpusvn       string
	verifyResult string
	tcbStatus    tcbstatus.Status
	err          error
}

func runEnclave(enclave []byte) runResult {
	if len(enclave) == 0 {
		return runResult{err: errors.New("not run (built without embedded test app)")}
	}

	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return runResult{err: err}
	}
	defer os.RemoveAll(dir)

	const filenameHost = "testapp_host"
	const filenameEnclave = "enclave.signed"
	if err := os.WriteFile(filepath.Join(dir, filenameHost), testappHost, 0o700); err != nil {
		return runResult{err: err}
	}
	if err := os.WriteFile(filepath.Join(dir, filenameEnclave), enclave, 0o600); err != nil {
		return runResult{err: err}
	}

	cmd := exec.Command("stdbuf", "-oL", "./"+filenameHost, filenameEnclave)
	cmd.Dir = dir
	return runCmd(cmd)
}

func runDocker(enclaveFilename string) runResult {
	cmd := exec.Command("docker", "run", "--rm", "-t", "-v/var/run/aesmd:/var/run/aesmd")
	for _, d := range []string{"/dev/sgx_enclave", "/dev/sgx_provision", "/dev/isgx"} {
		if st, err := os.Lstat(d); err == nil && st.Mode()&os.ModeDevice != 0 {
			cmd.Args = append(cmd.Args, "--device", d)
		}
	}
	cmd.Args = append(cmd.Args, "ghcr.io/edgelesssys/sgx-troubleshoot/testapp", enclaveFilename)
	return runCmd(cmd)
}

func runCmd(cmd *exec.Cmd) runResult {
	res := runResult{exitCode: 1, tcbStatus: tcbstatus.Unknown}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var eerr *exec.ExitError
		if !errors.As(err, &eerr) {
			res.err = err
			return res
		}
	}

	res.exitCode = cmd.ProcessState.ExitCode()

	if *verbose {
		fmt.Printf("%v\n%s\n", strings.Join(cmd.Args, " "), out)
	}

	if match := regexp.MustCompile(`CPUSVN: (\w+)`).FindSubmatch(out); match != nil {
		res.cpusvn = string(match[1])
	}
	if match := regexp.MustCompile(`VERIFYRESULT: (\w+)`).FindSubmatch(out); match != nil {
		res.verifyResult = string(match[1])
	}
	if match := regexp.MustCompile(`TCBSTATUS: (\d)`).FindSubmatch(out); match != nil {
		if status, err := strconv.Atoi(string(match[1])); err == nil {
			res.tcbStatus = tcbstatus.Status(status)
		}
	}

	return res
}

func (r runResult) write(wr io.Writer, caption string) {
	if r.err != nil {
		writeRow(wr, caption+" error", r.err)
		return
	}

	var desc string

	switch {
	case r.exitCode == 0:
		desc = "0 (success)"
	case r.exitCode == 1:
		desc = "1 (failed to launch enclave)"
	case 2 <= r.exitCode && r.exitCode <= ecMax:
		var failedFuncs []string
		if r.exitCode&ecGetLocalReport != 0 {
			failedFuncs = append(failedFuncs, "get_local_report")
		}
		if r.exitCode&ecVerifyLocalReport != 0 {
			failedFuncs = append(failedFuncs, "verify_local_report")
		}
		if r.exitCode&ecGetRemoteReport != 0 {
			failedFuncs = append(failedFuncs, "get_remote_report")
		}
		if r.exitCode&ecVerifyRemoteReport != 0 {
			failedFuncs = append(failedFuncs, "verify_remote_report")
		}
		desc = fmt.Sprintf("%v (attestation failed: %v)", r.exitCode, strings.Join(failedFuncs, ", "))
	default:
		desc = fmt.Sprintf("%v (unknown)", r.exitCode)
	}

	writeRow(wr, caption+" exit code", desc)
	if r.cpusvn != "" {
		writeRow(wr, caption+" CPUSVN", r.cpusvn)
	}
	if r.verifyResult != "" {
		writeRow(wr, caption+" RA result", r.verifyResult)
	}
	writeRow(wr, caption+" TCB status", fmt.Sprintf("%s (%v)", r.tcbStatus, tcbstatus.Explain(r.tcbStatus)))
}
