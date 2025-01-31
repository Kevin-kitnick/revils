package generate

/*
	Revils Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/Kevin-kitnick/revils/implant"
	"github.com/Kevin-kitnick/revils/protobuf/clientpb"
	"github.com/Kevin-kitnick/revils/server/assets"
	"github.com/Kevin-kitnick/revils/server/certs"
	"github.com/Kevin-kitnick/revils/server/configs"
	"github.com/Kevin-kitnick/revils/server/cryptography"
	"github.com/Kevin-kitnick/revils/server/db/models"
	"github.com/Kevin-kitnick/revils/server/gogo"
	"github.com/Kevin-kitnick/revils/server/log"
	"github.com/Kevin-kitnick/revils/util"
)

var (
	buildLog = log.NamedLogger("generate", "build")

	// RUNTIME GOOS -> TARGET GOOS -> TARGET ARCH
	defaultCCPaths = map[string]map[string]map[string]string{
		"linux": {
			"windows": {
				"386":   "/usr/bin/i686-w64-mingw32-gcc",
				"amd64": "/usr/bin/x86_64-w64-mingw32-gcc",
			},
			"darwin": {
				// OSX Cross - https://github.com/tpoechtrager/osxcross
				"amd64": "/opt/osxcross/target/bin/o64-clang",
				"arm64": "/opt/osxcross/target/bin/aarch64-apple-darwin20.2-clang",
			},
		},
		"darwin": {
			"windows": {
				"386":   "/opt/homebrew/bin/i686-w64-mingw32-gcc",
				"amd64": "/opt/homebrew/bin/x86_64-w64-mingw32-gcc",
			},
			"linux": {
				// brew install FiloSottile/musl-cross/musl-cross
				"amd64": "/opt/homebrew/bin/x86_64-linux-musl-gcc",
			},
		},
	}

	// SupportedCompilerTargets - Supported compiler targets
	SupportedCompilerTargets = map[string]bool{
		"darwin/amd64":  true,
		"darwin/arm64":  true,
		"linux/386":     true,
		"linux/amd64":   true,
		"windows/386":   true,
		"windows/amd64": true,
	}
)

const (
	RevilsTemplateName = "revils"

	// WINDOWS OS
	WINDOWS = "windows"

	// DARWIN / MacOS
	DARWIN = "darwin"

	// LINUX OS
	LINUX = "linux"

	clientsDirName = "clients"
	revilssDirName = "revilss"

	// DefaultReconnectInterval - In seconds
	DefaultReconnectInterval = 60
	// DefaultMTLSLPort - Default listen port
	DefaultMTLSLPort = 8888
	// DefaultHTTPLPort - Default HTTP listen port
	DefaultHTTPLPort = 443 // Assume SSL, it'll fallback
	// DefaultPollInterval - In seconds
	DefaultPollInterval = 1

	// DefaultSuffix - Indicates a platform independent src file
	DefaultSuffix = "_default.go"

	// *** Default ***

	// RevilsCC64EnvVar - Environment variable that can specify the 64 bit mingw path
	RevilsCC64EnvVar = "SLIVER_CC_64"
	// RevilsCC32EnvVar - Environment variable that can specify the 32 bit mingw path
	RevilsCC32EnvVar = "SLIVER_CC_32"

	// RevilsCXX64EnvVar - Environment variable that can specify the 64 bit mingw path
	RevilsCXX64EnvVar = "SLIVER_CXX_64"
	// RevilsCXX32EnvVar - Environment variable that can specify the 32 bit mingw path
	RevilsCXX32EnvVar = "SLIVER_CXX_32"

	// *** Platform Specific ***

	// RevilsPlatformCC64EnvVar - Environment variable that can specify the 64 bit mingw path
	RevilsPlatformCC64EnvVar = "SLIVER_%s_CC_64"
	// RevilsPlatformCC32EnvVar - Environment variable that can specify the 32 bit mingw path
	RevilsPlatformCC32EnvVar = "SLIVER_%s_CC_32"
	// RevilsPlatformCXX64EnvVar - Environment variable that can specify the 64 bit mingw path
	RevilsPlatformCXX64EnvVar = "SLIVER_%s_CXX_64"
	// RevilsPlatformCXX32EnvVar - Environment variable that can specify the 32 bit mingw path
	RevilsPlatformCXX32EnvVar = "SLIVER_%s_CXX_32"
)

// ImplantConfigFromProtobuf - Create a native config struct from Protobuf
func ImplantConfigFromProtobuf(pbConfig *clientpb.ImplantConfig) (string, *models.ImplantConfig) {
	cfg := &models.ImplantConfig{}

	cfg.IsBeacon = pbConfig.IsBeacon
	cfg.BeaconInterval = pbConfig.BeaconInterval
	cfg.BeaconJitter = pbConfig.BeaconJitter

	cfg.ECCServerPublicKey = pbConfig.ECCServerPublicKey
	cfg.ECCPrivateKey = pbConfig.ECCPrivateKey
	cfg.ECCPublicKey = pbConfig.ECCPublicKey

	cfg.GOOS = pbConfig.GOOS
	cfg.GOARCH = pbConfig.GOARCH
	cfg.MtlsCACert = pbConfig.MtlsCACert
	cfg.MtlsCert = pbConfig.MtlsCert
	cfg.MtlsKey = pbConfig.MtlsKey
	cfg.Debug = pbConfig.Debug
	cfg.DebugFile = pbConfig.DebugFile
	cfg.Evasion = pbConfig.Evasion
	cfg.ObfuscateSymbols = pbConfig.ObfuscateSymbols
	cfg.TemplateName = pbConfig.TemplateName
	if cfg.TemplateName == "" {
		cfg.TemplateName = RevilsTemplateName
	}
	cfg.ConnectionStrategy = pbConfig.ConnectionStrategy

	cfg.WGImplantPrivKey = pbConfig.WGImplantPrivKey
	cfg.WGServerPubKey = pbConfig.WGServerPubKey
	cfg.WGPeerTunIP = pbConfig.WGPeerTunIP
	cfg.WGKeyExchangePort = pbConfig.WGKeyExchangePort
	cfg.WGTcpCommsPort = pbConfig.WGTcpCommsPort
	cfg.ReconnectInterval = pbConfig.ReconnectInterval
	cfg.MaxConnectionErrors = pbConfig.MaxConnectionErrors

	cfg.LimitDomainJoined = pbConfig.LimitDomainJoined
	cfg.LimitDatetime = pbConfig.LimitDatetime
	cfg.LimitUsername = pbConfig.LimitUsername
	cfg.LimitHostname = pbConfig.LimitHostname
	cfg.LimitFileExists = pbConfig.LimitFileExists
	cfg.LimitLocale = pbConfig.LimitLocale

	cfg.Format = pbConfig.Format
	cfg.IsSharedLib = pbConfig.IsSharedLib
	cfg.IsService = pbConfig.IsService
	cfg.IsShellcode = pbConfig.IsShellcode

	cfg.RunAtLoad = pbConfig.RunAtLoad

	cfg.CanaryDomains = []models.CanaryDomain{}
	for _, pbCanary := range pbConfig.CanaryDomains {
		cfg.CanaryDomains = append(cfg.CanaryDomains, models.CanaryDomain{
			Domain: pbCanary,
		})
	}

	// Copy C2
	cfg.C2 = copyC2List(pbConfig.C2)
	cfg.MTLSc2Enabled = isC2Enabled([]string{"mtls"}, cfg.C2)
	cfg.WGc2Enabled = isC2Enabled([]string{"wg"}, cfg.C2)
	cfg.HTTPc2Enabled = isC2Enabled([]string{"http", "https"}, cfg.C2)
	cfg.DNSc2Enabled = isC2Enabled([]string{"dns"}, cfg.C2)
	cfg.NamePipec2Enabled = isC2Enabled([]string{"namedpipe"}, cfg.C2)
	cfg.TCPPivotc2Enabled = isC2Enabled([]string{"tcppivot"}, cfg.C2)

	if pbConfig.FileName != "" {
		cfg.FileName = path.Base(pbConfig.FileName)
	}

	name := ""
	if err := util.AllowedName(pbConfig.Name); err != nil {
		buildLog.Warnf("%s\n", err)
	} else {
		name = pbConfig.Name
	}
	return name, cfg
}

func copyC2List(src []*clientpb.ImplantC2) []models.ImplantC2 {
	c2s := []models.ImplantC2{}
	for _, srcC2 := range src {
		c2URL, err := url.Parse(srcC2.URL)
		if err != nil {
			buildLog.Warnf("Failed to parse c2 url %v", err)
			continue
		}
		c2s = append(c2s, models.ImplantC2{
			Priority: srcC2.Priority,
			URL:      c2URL.String(),
			Options:  srcC2.Options,
		})
	}
	return c2s
}

func isC2Enabled(schemes []string, c2s []models.ImplantC2) bool {
	for _, c2 := range c2s {
		c2URL, err := url.Parse(c2.URL)
		if err != nil {
			buildLog.Warnf("Failed to parse c2 url %v", err)
			continue
		}
		for _, scheme := range schemes {
			if scheme == c2URL.Scheme {
				return true
			}
		}
	}
	buildLog.Debugf("No %v URLs found in %v", schemes, c2s)
	return false
}

// GetRevilssDir - Get the binary directory
func GetRevilssDir() string {
	appDir := assets.GetRootAppDir()
	revilssDir := path.Join(appDir, revilssDirName)
	if _, err := os.Stat(revilssDir); os.IsNotExist(err) {
		buildLog.Debugf("Creating bin directory: %s", revilssDir)
		err = os.MkdirAll(revilssDir, 0700)
		if err != nil {
			buildLog.Fatal(err)
		}
	}
	return revilssDir
}

// -----------------------
// Revils Generation Code
// -----------------------

// RevilsShellcode - Generates a revils shellcode using Donut
func RevilsShellcode(name string, otpSecret string, config *models.ImplantConfig, save bool) (string, error) {
	if config.GOOS != "windows" {
		return "", fmt.Errorf("shellcode format is currently only supported on Windows")
	}
	appDir := assets.GetRootAppDir()
	goConfig := &gogo.GoConfig{
		CGO: "0",

		GOOS:       config.GOOS,
		GOARCH:     config.GOARCH,
		GOCACHE:    gogo.GetGoCache(appDir),
		GOMODCACHE: gogo.GetGoModCache(appDir),
		GOROOT:     gogo.GetGoRootDir(appDir),
		GOPROXY:    getGoProxy(),
		HTTPPROXY:  getGoHttpProxy(),
		HTTPSPROXY: getGoHttpsProxy(),

		Obfuscation: config.ObfuscateSymbols,
		GOGARBLE:    goPrivate(config),
	}
	pkgPath, err := renderRevilsGoCode(name, otpSecret, config, goConfig)
	if err != nil {
		return "", err
	}

	dest := filepath.Join(goConfig.ProjectDir, "bin", filepath.Base(name))
	dest += ".bin"

	tags := []string{} // []string{"netgo"}
	ldflags := []string{"-s -w -buildid="}
	if !config.Debug && goConfig.GOOS == WINDOWS {
		ldflags[0] += " -H=windowsgui"
	}
	// Keep those for potential later use
	gcflags := ""
	asmflags := ""
	// trimpath is now a separate flag since Go 1.13
	trimpath := "-trimpath"
	_, err = gogo.GoBuild(*goConfig, pkgPath, dest, "pie", tags, ldflags, gcflags, asmflags, trimpath)
	if err != nil {
		return "", err
	}
	config.FileName = path.Base(dest)
	shellcode, err := DonutShellcodeFromFile(dest, config.GOARCH, false, "", "", "")
	if err != nil {
		return "", err
	}
	err = os.WriteFile(dest, shellcode, 0600)
	if err != nil {
		return "", err
	}
	config.Format = clientpb.OutputFormat_SHELLCODE
	// Save to database
	if save {
		saveBuildErr := ImplantBuildSave(name, config, dest)
		if saveBuildErr != nil {
			buildLog.Errorf("Failed to save build: %s", saveBuildErr)
		}
	}
	return dest, err

}

// RevilsSharedLibrary - Generates a revils shared library (DLL/dylib/so) binary
func RevilsSharedLibrary(name string, otpSecret string, config *models.ImplantConfig, save bool) (string, error) {
	// Compile go code
	var cc string
	var cxx string

	appDir := assets.GetRootAppDir()
	// Don't use a cross-compiler if the target bin is built on the same platform
	// as the revils-server.
	if runtime.GOOS != config.GOOS {
		buildLog.Debugf("Cross-compiling from %s/%s to %s/%s", runtime.GOOS, runtime.GOARCH, config.GOOS, config.GOARCH)
		cc, cxx = findCrossCompilers(config.GOOS, config.GOARCH)
		if cc == "" {
			return "", fmt.Errorf("CC '%s/%s' not found", config.GOOS, config.GOARCH)
		}
	}
	goConfig := &gogo.GoConfig{
		CGO: "1",
		CC:  cc,
		CXX: cxx,

		GOOS:       config.GOOS,
		GOARCH:     config.GOARCH,
		GOCACHE:    gogo.GetGoCache(appDir),
		GOMODCACHE: gogo.GetGoModCache(appDir),
		GOROOT:     gogo.GetGoRootDir(appDir),
		GOPROXY:    getGoProxy(),
		HTTPPROXY:  getGoHttpProxy(),
		HTTPSPROXY: getGoHttpsProxy(),

		Obfuscation: config.ObfuscateSymbols,
		GOGARBLE:    goPrivate(config),
	}
	pkgPath, err := renderRevilsGoCode(name, otpSecret, config, goConfig)
	if err != nil {
		return "", err
	}

	dest := filepath.Join(goConfig.ProjectDir, "bin", filepath.Base(name))
	if goConfig.GOOS == WINDOWS {
		dest += ".dll"
	}
	if goConfig.GOOS == DARWIN {
		dest += ".dylib"
	}
	if goConfig.GOOS == LINUX {
		dest += ".so"
	}

	tags := []string{} // []string{"netgo"}
	ldflags := []string{"-s -w -buildid="}
	if !config.Debug && goConfig.GOOS == WINDOWS {
		ldflags[0] += " -H=windowsgui"
	}
	// Statically link Linux .so files to avoid glibc hell
	if goConfig.GOOS == LINUX && goConfig.CC != "" && goConfig.CGO == "1" {
		ldflags[0] += " -linkmode external -extldflags \"-static\""
	}
	// Keep those for potential later use
	gcflags := ""
	asmflags := ""
	// trimpath is now a separate flag since Go 1.13
	trimpath := "-trimpath"
	_, err = gogo.GoBuild(*goConfig, pkgPath, dest, "c-shared", tags, ldflags, gcflags, asmflags, trimpath)
	if err != nil {
		return "", err
	}
	config.FileName = filepath.Base(dest)

	if save {
		err = ImplantBuildSave(name, config, dest)
		if err != nil {
			buildLog.Errorf("Failed to save build: %s", err)
		}
	}
	return dest, err
}

// RevilsExecutable - Generates a revils executable binary
func RevilsExecutable(name string, otpSecret string, config *models.ImplantConfig, save bool) (string, error) {
	// Compile go code
	appDir := assets.GetRootAppDir()
	cgo := "0"
	if config.IsSharedLib {
		cgo = "1"
	}

	goConfig := &gogo.GoConfig{
		CGO:        cgo,
		GOOS:       config.GOOS,
		GOARCH:     config.GOARCH,
		GOROOT:     gogo.GetGoRootDir(appDir),
		GOCACHE:    gogo.GetGoCache(appDir),
		GOMODCACHE: gogo.GetGoModCache(appDir),
		GOPROXY:    getGoProxy(),
		HTTPPROXY:  getGoHttpProxy(),
		HTTPSPROXY: getGoHttpsProxy(),

		Obfuscation: config.ObfuscateSymbols,
		GOGARBLE:    goPrivate(config),
	}

	pkgPath, err := renderRevilsGoCode(name, otpSecret, config, goConfig)
	if err != nil {
		return "", err
	}

	dest := filepath.Join(goConfig.ProjectDir, "bin", filepath.Base(name))
	if goConfig.GOOS == WINDOWS {
		dest += ".exe"
	}
	tags := []string{} // []string{"netgo"}
	ldflags := []string{"-s -w -buildid="}
	if !config.Debug && goConfig.GOOS == WINDOWS {
		ldflags[0] += " -H=windowsgui"
	}
	gcflags := ""
	asmflags := ""
	if config.Debug {
		gcflags = "all=-N -l"
		ldflags = []string{}
	}
	// trimpath is now a separate flag since Go 1.13
	trimpath := ""
	if !config.Debug {
		trimpath = "-trimpath"
	}
	_, err = gogo.GoBuild(*goConfig, pkgPath, dest, "", tags, ldflags, gcflags, asmflags, trimpath)
	if err != nil {
		return "", err
	}
	config.FileName = filepath.Base(dest)
	if save {
		err = ImplantBuildSave(name, config, dest)
		if err != nil {
			buildLog.Errorf("Failed to save build: %s", err)
		}
	}
	return dest, err
}

// This function is a little too long, we should probably refactor it as some point
func renderRevilsGoCode(name string, otpSecret string, config *models.ImplantConfig, goConfig *gogo.GoConfig) (string, error) {
	target := fmt.Sprintf("%s/%s", config.GOOS, config.GOARCH)
	if _, ok := gogo.ValidCompilerTargets(*goConfig)[target]; !ok {
		return "", fmt.Errorf("invalid compiler target: %s", target)
	}
	if name == "" {
		return "", fmt.Errorf("name cannot be empty")
	}

	buildLog.Debugf("Generating new revils binary '%s'", name)

	revilssDir := GetRevilssDir() // ~/.revils/revilss
	projectGoPathDir := filepath.Join(revilssDir, config.GOOS, config.GOARCH, filepath.Base(name))
	if _, err := os.Stat(projectGoPathDir); os.IsNotExist(err) {
		os.MkdirAll(projectGoPathDir, 0700)
	}
	goConfig.ProjectDir = projectGoPathDir

	// binDir - ~/.revils/revilss/<os>/<arch>/<name>/bin
	binDir := filepath.Join(projectGoPathDir, "bin")
	os.MkdirAll(binDir, 0700)

	// srcDir - ~/.revils/revilss/<os>/<arch>/<name>/src
	srcDir := filepath.Join(projectGoPathDir, "src")
	assets.SetupGoPath(srcDir)             // Extract GOPATH dependency files
	err := util.ChmodR(srcDir, 0600, 0700) // Ensures src code files are writable
	if err != nil {
		buildLog.Errorf("fs perms: %v", err)
		return "", err
	}

	revilsPkgDir := filepath.Join(srcDir, "github.com", "Kevin-kitnick", "revils") // "main"
	err = os.MkdirAll(revilsPkgDir, 0700)
	if err != nil {
		return "", nil
	}

	err = fs.WalkDir(implant.FS, ".", func(fsPath string, f fs.DirEntry, err error) error {
		if f.IsDir() {
			return nil
		}
		buildLog.Debugf("Walking: %s %s %v", fsPath, f.Name(), err)

		revilsGoCodeRaw, err := implant.FS.ReadFile(fsPath)
		if err != nil {
			buildLog.Errorf("Failed to read %s: %s", fsPath, err)
			return nil
		}
		revilsGoCode := string(revilsGoCodeRaw)

		// Skip dllmain files for anything non windows
		if f.Name() == "revils.c" || f.Name() == "revils.h" {
			if !config.IsSharedLib && !config.IsShellcode {
				return nil
			}
		}

		var revilsCodePath string
		if f.Name() == "revils.go" || f.Name() == "revils.c" || f.Name() == "revils.h" {
			revilsCodePath = filepath.Join(revilsPkgDir, f.Name())
		} else {
			revilsCodePath = filepath.Join(revilsPkgDir, "implant", fsPath)
		}
		dirPath := filepath.Dir(revilsCodePath)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			buildLog.Debugf("[mkdir] %#v", dirPath)
			err = os.MkdirAll(dirPath, 0700)
			if err != nil {
				return err
			}
		}
		fRevils, err := os.Create(revilsCodePath)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer([]byte{})
		buildLog.Debugf("[render] %s -> %s", f.Name(), revilsCodePath)

		// --------------
		// Render Code
		// --------------
		revilsCodeTmpl := template.New("revils")
		revilsCodeTmpl, err = revilsCodeTmpl.Funcs(template.FuncMap{
			"GenerateUserAgent": func() string {
				return configs.GetHTTPC2Config().GenerateUserAgent(config.GOOS, config.GOARCH)
			},
		}).Parse(revilsGoCode)
		if err != nil {
			buildLog.Errorf("Template parsing error %s", err)
			return err
		}
		err = revilsCodeTmpl.Execute(buf, struct {
			Name                string
			Config              *models.ImplantConfig
			OTPSecret           string
			HTTPC2ImplantConfig *configs.HTTPC2ImplantConfig
		}{
			name,
			config,
			otpSecret,
			configs.GetHTTPC2Config().RandomImplantConfig(),
		})
		if err != nil {
			buildLog.Errorf("Template execution error %s", err)
			return err
		}

		// Render canaries
		if len(config.CanaryDomains) > 0 {
			buildLog.Debugf("Canary domain(s): %v", config.CanaryDomains)
		}
		canaryTmpl := template.New("canary").Delims("[[", "]]")
		canaryGenerator := &CanaryGenerator{
			ImplantName:   name,
			ParentDomains: config.CanaryDomainsList(),
		}
		canaryTmpl, err = canaryTmpl.Funcs(template.FuncMap{
			"GenerateCanary": canaryGenerator.GenerateCanary,
		}).Parse(buf.String())
		if err != nil {
			return err
		}
		err = canaryTmpl.Execute(fRevils, canaryGenerator)

		if err != nil {
			buildLog.Debugf("Failed to render go code: %s", err)
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	// Render GoMod
	buildLog.Info("Rendering go.mod file ...")
	goModPath := filepath.Join(revilsPkgDir, "go.mod")
	err = os.WriteFile(goModPath, []byte(implant.GoMod), 0600)
	if err != nil {
		return "", err
	}
	goSumPath := filepath.Join(revilsPkgDir, "go.sum")
	err = os.WriteFile(goSumPath, []byte(implant.GoSum), 0600)
	if err != nil {
		return "", err
	}
	// Render vendor dir
	err = fs.WalkDir(implant.Vendor, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return os.MkdirAll(filepath.Join(revilsPkgDir, path), 0700)
		}

		contents, err := implant.Vendor.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(filepath.Join(revilsPkgDir, path), contents, 0600)
	})
	if err != nil {
		buildLog.Errorf("Failed to copy vendor directory %v", err)
		return "", err
	}
	buildLog.Debugf("Created %s", goModPath)

	return revilsPkgDir, nil
}

// GenerateConfig - Generate the keys/etc for the implant
func GenerateConfig(name string, config *models.ImplantConfig, save bool) error {
	var err error

	config.MTLSc2Enabled = isC2Enabled([]string{"mtls"}, config.C2)
	config.WGc2Enabled = isC2Enabled([]string{"wg"}, config.C2)
	config.HTTPc2Enabled = isC2Enabled([]string{"http", "https"}, config.C2)
	config.DNSc2Enabled = isC2Enabled([]string{"dns"}, config.C2)
	config.NamePipec2Enabled = isC2Enabled([]string{"namedpipe"}, config.C2)
	config.TCPPivotc2Enabled = isC2Enabled([]string{"tcppivot"}, config.C2)

	// Cert PEM encoded certificates
	serverCACert, _, _ := certs.GetCertificateAuthorityPEM(certs.MtlsServerCA)
	revilsCert, revilsKey, err := certs.MtlsC2ImplantGenerateECCCertificate(name)
	if err != nil {
		return err
	}

	// ECC keys
	implantKeyPair, err := cryptography.RandomAgeKeyPair()
	if err != nil {
		return err
	}
	serverKeyPair := cryptography.ECCServerKeyPair()
	digest := sha256.Sum256([]byte(implantKeyPair.Public))
	config.ECCPublicKey = implantKeyPair.Public
	config.ECCPublicKeyDigest = hex.EncodeToString(digest[:])
	config.ECCPrivateKey = implantKeyPair.Private
	config.ECCPublicKeySignature = cryptography.MinisignServerSign([]byte(implantKeyPair.Public))
	config.ECCServerPublicKey = serverKeyPair.Public
	config.MinisignServerPublicKey = cryptography.MinisignServerPublicKey()

	// MTLS keys
	if config.MTLSc2Enabled {
		config.MtlsCACert = string(serverCACert)
		config.MtlsCert = string(revilsCert)
		config.MtlsKey = string(revilsKey)
	}

	// Generate wg Keys as needed
	if config.WGc2Enabled {
		implantPrivKey, _, err := certs.ImplantGenerateWGKeys(config.WGPeerTunIP)
		if err != nil {
			return err
		}
		_, serverPubKey, err := certs.GetWGServerKeys()
		if err != nil {
			return fmt.Errorf("failed to embed implant wg keys: %s", err)
		}
		config.WGImplantPrivKey = implantPrivKey
		config.WGServerPubKey = serverPubKey
	}

	if save {
		err = ImplantConfigSave(config)
		if err != nil {
			return err
		}
	}
	return nil
}

// Platform specific ENV VARS take precedence over generic
func getCrossCompilersFromEnv(targetGoos string, targetGoarch string) (string, string) {
	var cc string
	var cxx string

	TARGET_GOOS := strings.ToUpper(targetGoos)

	// Get Defaults
	if targetGoarch == "amd64" {
		if os.Getenv(fmt.Sprintf(RevilsPlatformCC64EnvVar, TARGET_GOOS)) != "" {
			cc = os.Getenv(fmt.Sprintf(RevilsPlatformCC64EnvVar, TARGET_GOOS))
		}
		if cc == "" {
			cc = os.Getenv(RevilsCC64EnvVar)
		}
		if os.Getenv(fmt.Sprintf(RevilsPlatformCXX64EnvVar, TARGET_GOOS)) != "" {
			cc = os.Getenv(fmt.Sprintf(RevilsPlatformCXX64EnvVar, TARGET_GOOS))
		}
		if cxx == "" {
			cxx = os.Getenv(RevilsCXX64EnvVar)
		}
	}
	if targetGoarch == "386" {
		cc = os.Getenv(RevilsCC32EnvVar)
		if os.Getenv(fmt.Sprintf(RevilsPlatformCC32EnvVar, TARGET_GOOS)) != "" {
			cc = os.Getenv(fmt.Sprintf(RevilsPlatformCC32EnvVar, TARGET_GOOS))
		}
		cxx = os.Getenv(RevilsCXX64EnvVar)
		if os.Getenv(fmt.Sprintf(RevilsPlatformCXX32EnvVar, TARGET_GOOS)) != "" {
			cc = os.Getenv(fmt.Sprintf(RevilsPlatformCXX32EnvVar, TARGET_GOOS))
		}
	}
	return cc, cxx
}

func findCrossCompilers(targetGoos string, targetGoarch string) (string, string) {
	var found bool

	// Get CC and CXX from ENV
	cc, cxx := getCrossCompilersFromEnv(targetGoos, targetGoarch)

	// If no CC is set in ENV then look for default path(s), we need a CC
	// but don't always need a CXX so we only WARN on a missing CXX
	if cc == "" {
		buildLog.Debugf("CC not found in ENV, using default paths")
		if _, ok := defaultCCPaths[runtime.GOOS]; ok {
			if cc, found = defaultCCPaths[runtime.GOOS][targetGoos][targetGoarch]; !found {
				buildLog.Debugf("No default for %s/%s from %s", targetGoos, targetGoarch, runtime.GOOS)
			}
		} else {
			buildLog.Debugf("No default paths for %s runtime", runtime.GOOS)
		}
	}

	// Check to see if CC and CXX exist
	if cc != "" {
		if _, err := os.Stat(cc); os.IsNotExist(err) {
			buildLog.Warnf("CC path '%s' does not exist", cc)
		}
	}
	buildLog.Debugf(" CC = '%s'", cc)
	if cxx != "" {
		if _, err := os.Stat(cxx); os.IsNotExist(err) {
			buildLog.Warnf("CXX path '%s' does not exist", cxx)
		}
	}
	buildLog.Debugf("CXX = '%s'", cxx)
	return cc, cxx
}

// GetCompilerTargets - This function attempts to determine what we can reasonably target
func GetCompilerTargets() []*clientpb.CompilerTarget {
	targets := []*clientpb.CompilerTarget{}

	// EXE - Any server should be able to target EXEs of each platform
	for longPlatform := range SupportedCompilerTargets {
		platform := strings.SplitN(longPlatform, "/", 2)
		targets = append(targets, &clientpb.CompilerTarget{
			GOOS:   platform[0],
			GOARCH: platform[1],
			Format: clientpb.OutputFormat_EXECUTABLE,
		})
	}

	// SHARED_LIB - Determine if we can probably build a dll/dylib/so
	for longPlatform := range SupportedCompilerTargets {
		platform := strings.SplitN(longPlatform, "/", 2)

		// We can always build our own platform
		if runtime.GOOS == platform[0] {
			targets = append(targets, &clientpb.CompilerTarget{
				GOOS:   platform[0],
				GOARCH: platform[1],
				Format: clientpb.OutputFormat_SHARED_LIB,
			})
			continue
		}

		// Cross-compile with the right configuration
		if runtime.GOOS == LINUX || runtime.GOOS == DARWIN {
			cc, _ := findCrossCompilers(platform[0], platform[1])
			if cc != "" {
				if runtime.GOOS == DARWIN && platform[0] == LINUX && platform[1] == "386" {
					continue // Darwin can't target 32-bit Linux, even with a cc/cxx
				}
				targets = append(targets, &clientpb.CompilerTarget{
					GOOS:   platform[0],
					GOARCH: platform[1],
					Format: clientpb.OutputFormat_SHARED_LIB,
				})
			}
		}

	}

	// SERVICE - Can generate service executables for Windows targets only
	for longPlatform := range SupportedCompilerTargets {
		platform := strings.SplitN(longPlatform, "/", 2)
		if platform[0] != WINDOWS {
			continue
		}

		targets = append(targets, &clientpb.CompilerTarget{
			GOOS:   platform[0],
			GOARCH: platform[1],
			Format: clientpb.OutputFormat_SERVICE,
		})
	}

	// SHELLCODE - Can generate shellcode for Windows targets only
	for longPlatform := range SupportedCompilerTargets {
		platform := strings.SplitN(longPlatform, "/", 2)
		if platform[0] != WINDOWS {
			continue
		}

		targets = append(targets, &clientpb.CompilerTarget{
			GOOS:   platform[0],
			GOARCH: platform[1],
			Format: clientpb.OutputFormat_SHELLCODE,
		})
	}

	return targets
}

// GetCrossCompilers - Get information about the server's cross-compiler configuration
func GetCrossCompilers() []*clientpb.CrossCompiler {
	compilers := []*clientpb.CrossCompiler{}
	for longPlatform := range SupportedCompilerTargets {
		platform := strings.SplitN(longPlatform, "/", 2)
		if runtime.GOOS == platform[0] {
			continue
		}
		cc, cxx := findCrossCompilers(platform[0], platform[1])
		if cc != "" {
			compilers = append(compilers, &clientpb.CrossCompiler{
				TargetGOOS:   platform[0],
				TargetGOARCH: platform[1],
				CCPath:       cc,
				CXXPath:      cxx,
			})
		}
	}
	return compilers
}

// GetUnsupportedTargets - Get compiler targets that are not "supported" on this platform
func GetUnsupportedTargets() []*clientpb.CompilerTarget {
	appDir := assets.GetRootAppDir()
	distList := gogo.GoToolDistList(gogo.GoConfig{
		GOCACHE:    gogo.GetGoCache(appDir),
		GOMODCACHE: gogo.GetGoModCache(appDir),
		GOROOT:     gogo.GetGoRootDir(appDir),
	})
	targets := []*clientpb.CompilerTarget{}
	for _, dist := range distList {
		if _, ok := SupportedCompilerTargets[dist]; ok {
			continue
		}
		parts := strings.SplitN(dist, "/", 2)
		if len(parts) != 2 {
			continue
		}
		targets = append(targets, &clientpb.CompilerTarget{
			GOOS:   parts[0],
			GOARCH: parts[1],
			Format: clientpb.OutputFormat_EXECUTABLE,
		})
	}
	return targets
}

func getGoProxy() string {
	serverConfig := configs.GetServerConfig()
	if serverConfig.GoProxy != "" {
		buildLog.Debugf("Using GOPROXY from server config = %s", serverConfig.GoProxy)
		return serverConfig.GoProxy
	}
	value, present := os.LookupEnv("GOPROXY")
	if present {
		buildLog.Debugf("Using GOPROXY from env: %s", value)
		return value
	}
	const defaultGoProxy = "off"
	buildLog.Debugf("No GOPROXY setting found, default to %s", defaultGoProxy)
	return defaultGoProxy
}

func getGoHttpProxy() string {
	value, present := os.LookupEnv("HTTP_PROXY")
	if present {
		buildLog.Debugf("Using HTTP_PROXY from env: %s", value)
		return value
	}
	buildLog.Debugf("No HTTP_PROXY found")
	return ""
}

func getGoHttpsProxy() string {
	value, present := os.LookupEnv("HTTPS_PROXY")
	if present {
		buildLog.Debugf("Using HTTPS_PROXY from env: %s", value)
		return value
	}
	buildLog.Debugf("No HTTPS_PROXY found")
	return ""
}

const (
	// The wireguard garble bug appears to have been fixed.
	// Updated the wgGoPrivate to "*"
	// wgGoPrivate  = "*"
	allGoPrivate = "*"
)

func goPrivate(config *models.ImplantConfig) string {
	// for _, c2 := range config.C2 {
	// 	uri, err := url.Parse(c2.URL)
	// 	if err != nil {
	// 		return wgGoPrivate
	// 	}
	// 	if uri.Scheme == "wg" {
	// 		return wgGoPrivate
	// 	}
	// }
	return allGoPrivate
}
