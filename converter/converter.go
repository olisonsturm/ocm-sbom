// Package converter provides functionality to convert OCM component descriptors to various SBOM formats.
package converter

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// SBOMFormat represents the format of the SBOM to be generated.
type SBOMFormat string

const (
	FormatCycloneDXJSON SBOMFormat = "cyclonedx-json"
	FormatSPDXJSON      SBOMFormat = "spdx-json"
	FormatCycloneDXYAML SBOMFormat = "cyclonedx-yaml"
	FormatSPDXYAML      SBOMFormat = "spdx-yaml"
)

// SBOMConverter defines the interface for converting OCM component descriptors to SBOM formats.
type SBOMConverter interface {
	ConvertOCMToSBOM(ocmDescriptorPath string, targetFormat SBOMFormat, mergeTool string, convertTool string) ([]byte, error)
}

// CLIConverter is the implementation of SBOMConverter that uses command-line tools to perform the conversion and merging of SBOMs.
type CLIConverter struct {
	HopprCLIPath     string
	CycloneDXCLIPath string
	ProtobomCLIPath  string
	SyftCLIPath      string
	TempDir          string
}

// NewCLIConverter creates a new instance of CLIConverter.
// It initializes the paths for the required CLI tools and creates a temporary directory for intermediate files.
func NewCLIConverter(hopprPath, cyclonedxPath, protobomPath, syftPath, tempDir string) (*CLIConverter, error) {
	var err error
	if hopprPath == "" {
		hopprPath, _ = exec.LookPath("hopctl")
	}
	if cyclonedxPath == "" {
		cyclonedxPath, _ = exec.LookPath("cyclonedx")
	}
	if protobomPath == "" {
		protobomPath, _ = exec.LookPath("sbom-convert")
	}
	if syftPath == "" { // NEU: Syft-Pfad suchen
		syftPath, _ = exec.LookPath("syft")
	}

	if hopprPath == "" {
		log.Println("Hoppr (hopctl) CLI not found.")
		hopprPath, err = tryInstallCLI("hopctl")
		if err != nil {
			return nil, fmt.Errorf("failed to install hopctl: %w", err)
		}
	}
	if cyclonedxPath == "" {
		log.Println("CycloneDX CLI (cyclonedx) not found.")
		cyclonedxPath, err = tryInstallCLI("cyclonedx")
		if err != nil {
			return nil, fmt.Errorf("failed to install cyclonedx CLI: %w", err)
		}
	}
	if protobomPath == "" {
		log.Println("Protobom CLI (sbom-convert) not found.")
		protobomPath, err = tryInstallCLI("sbom-convert")
		if err != nil {
			return nil, fmt.Errorf("failed to install sbom-convert: %w", err)
		}
	}
	if syftPath == "" { // NEU: Syft-Installation versuchen
		log.Println("Syft CLI (syft) not found.")
		syftPath, err = tryInstallCLI("syft")
		if err != nil {
			return nil, fmt.Errorf("failed to install syft: %w", err)
		}
	}

	if tempDir == "" {
		tempDir, err = os.MkdirTemp("", "ocm-sbom-conv-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory: %w", err)
		}
	}

	return &CLIConverter{
		HopprCLIPath:     hopprPath,
		CycloneDXCLIPath: cyclonedxPath,
		ProtobomCLIPath:  protobomPath,
		SyftCLIPath:      syftPath, // NEU
		TempDir:          tempDir,
	}, nil
}

// CleanupTempDir deletes the temporary directory used for intermediate files.
func (c *CLIConverter) CleanupTempDir() error {
	if c.TempDir != "" {
		log.Printf("Cleaning up temporary directory: %s\n", c.TempDir)
		// TODO return os.RemoveAll(c.TempDir)
	}
	return nil
}

// runCommand will process a command with the given name and arguments.
func (c *CLIConverter) runCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("command '%s %s' failed: %w\nOutput:\n%s", name, strings.Join(args, " "), err, string(output))
	}
	return output, nil
}

// tryInstallCLI try to install a CLI tool if it is not found in the PATH.
func tryInstallCLI(cliName string) (string, error) {
	// Check if the CLI tool is already installed
	if path, err := exec.LookPath(cliName); err == nil && path != "" {
		log.Printf("%s found at %s. No installation needed.", cliName, path)
		return path, nil
	}

	installCmd, installArgs, installMethod, err := getInstallCommand(cliName)
	if err != nil {
		log.Printf("Could not determine installation method for %s: %v. Please install manually.", cliName, err)
		return "", fmt.Errorf("%s not found and cannot determine auto-install method. Please install manually", cliName)
	}

	if !promptForConfirmation(fmt.Sprintf("%s not found. Do you want to install it using '%s %s'? (y/N)", cliName, installCmd, strings.Join(installArgs, " "))) {
		return "", fmt.Errorf("user declined to install %s. Please install manually", cliName)
	}

	log.Printf("Attempting to install %s using %s...\n", cliName, installMethod)

	// WARNING for hopctl installation:
	if cliName == "hopctl" && installMethod == "pip" {
		log.Println("--- IMPORTANT NOTE for hopctl installation: ---")
		log.Println("After pip installation, 'hopctl' might not be directly in your system's PATH.")
		log.Println("You might need to add the pip bin directory (e.g., ~/.local/bin or virtual environment bin) to your PATH,")
		log.Println("or activate the virtual environment if one was used, for 'hopctl' to be found.")
		log.Println("If 'hopctl' is still not found, please refer to https://hoppr.dev/ for manual installation instructions.")
		log.Println("----------------------------------------------")
	}
	// WARNING for cyclonedx installation:
	if cliName == "syft" && installMethod == "curl" {
		log.Println("--- IMPORTANT NOTE for Syft installation: ---")
		log.Println("Syft is being installed via a curl script. Ensure you trust the source (https://anchore.com/syft).")
		log.Println("The script might install Syft to /usr/local/bin or a similar location. Ensure this is in your PATH.")
		log.Println("----------------------------------------------")
	}

	// perform the installation
	cmd := exec.Command(installCmd, installArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to execute installation command for %s: %w. Please try to install manually", cliName, err)
	}

	// After installation, check if the CLI is now available
	path, err := exec.LookPath(cliName)
	if err != nil || path == "" {
		return "", fmt.Errorf("%s installed but not found in PATH. Ensure %s is in your PATH environment variable. Error: %w", cliName, installMethod, err)
	}

	log.Printf("%s successfully installed and found at %s.", cliName, path)
	return path, nil
}

// promptForConfirmation asks the user for confirmation before proceeding with an action.
func promptForConfirmation(prompt string) bool {
	fmt.Printf("%s ", prompt)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y"
}

// getInstallCommand returns the command and arguments needed to install a CLI tool.
func getInstallCommand(cliName string) (command string, args []string, method string, err error) {
	// Überprüfen, ob python3 verfügbar ist
	python3Path, python3Err := exec.LookPath("python3")
	hasPython3 := python3Err == nil

	// Überprüfen, ob go verfügbar ist
	goBinPath, goPathErr := exec.LookPath("go")
	hasGo := goPathErr == nil

	// Überprüfen, ob curl verfügbar ist (für Syft)
	curlPath, curlErr := exec.LookPath("curl")
	hasCurl := curlErr == nil

	// Überprüfen, ob brew verfügbar ist (nur macOS)
	var hasBrew bool
	if runtime.GOOS == "darwin" {
		_, brewErr := exec.LookPath("brew")
		hasBrew = brewErr == nil
	}

	switch cliName {
	case "hopctl":
		if hasPython3 {
			return python3Path, []string{"-m", "pip", "install", "hoppr"}, "pip", nil
		}
		return "", nil, "", fmt.Errorf("python3 not found. Please install Python 3.10+ and then install hopctl manually via 'python3 -m pip install hoppr'")
	case "cyclonedx":
		if hasBrew { // macOS bevorzugt brew für cyclonedx-cli
			return "brew", []string{"install", "cyclonedx/cyclonedx/cyclonedx-cli"}, "brew install", nil
		}
		if hasGo { // Fallback auf go install, wenn brew nicht verfügbar oder nicht macOS
			return goBinPath, []string{"install", "github.com/CycloneDX/cyclonedx-cli/cmd/cyclonedx@latest"}, "go install", nil
		}
		return "", nil, "", fmt.Errorf("no automatic installation method (brew or go) found. Please install cyclonedx CLI manually")
	case "sbom-convert":
		if hasGo {
			return goBinPath, []string{"install", "github.com/protobom/sbom-convert/cmd/sbom-convert@latest"}, "go install", nil
		}
		return "", nil, "", fmt.Errorf("go not found. Please install Go and then install sbom-convert manually via 'go install github.com/protobom/sbom-convert/cmd/sbom-convert@latest'")
	case "syft":
		if hasBrew { // macOS bevorzugt brew für syft
			return "brew", []string{"install", "syft"}, "brew install", nil
		}
		if hasCurl { // Fallback auf curl script für Linux/macOS
			// Dies ist eine gängige Installationsmethode für Syft
			return "bash", []string{"-c", curlPath + " -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"}, "curl script", nil
		}
		if hasGo { // Syft kann auch via Go installiert werden, aber curl/brew sind oft einfacher
			return goBinPath, []string{"install", "github.com/anchore/syft/cmd/syft@latest"}, "go install", nil
		}
		return "", nil, "", fmt.Errorf("no automatic installation method (brew, curl, or go) found. Please install Syft manually")
	}

	return "", nil, "", fmt.Errorf("no automatic installation method found for %s on %s. Please install manually", cliName, runtime.GOOS)
}

// sanitizeFilename replaces problematic characters in filenames
func sanitizeFilename(filename string) string {
	// Replace common problematic characters
	replacements := map[string]string{
		"/":  "-",
		"\\": "-",
		":":  "-",
		"*":  "-",
		"?":  "-",
		"\"": "-",
		"<":  "-",
		">":  "-",
		"|":  "-",
	}

	result := filename
	for old, replacement := range replacements {
		result = strings.Replace(result, old, replacement, -1)
	}
	return result
}
