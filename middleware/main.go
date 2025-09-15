package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"io/ioutil"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"gopkg.in/yaml.v3"
)

type Middleware struct {
	Type   string            `yaml:"type"`
	Set    map[string]string `yaml:"set,omitempty"`
	Remove []string          `yaml:"remove,omitempty"`
	Users  map[string]string `yaml:"users,omitempty"`
	Routes []string          `yaml:"routes,omitempty"`
}

type Config struct {
	Middlewares []Middleware `yaml:"middlewares"`
}

func loadConfig(configDir string) (*Config, error) {
	path := filepath.Join(configDir, "middlewares.yml")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func startApp(appPath string, appPort int, args []string) (func(), error) {
	stat, err := os.Stat(appPath)
	if err != nil {
		return nil, err
	}

	// Case 1: Directory (Go project or working dir for other apps)
	if stat.IsDir() {
		// Go project? auto-build
		hasGo := fileExists(filepath.Join(appPath, "go.mod")) || fileExists(filepath.Join(appPath, "main.go"))
		if hasGo && len(args) == 0 {
			binPath := filepath.Join(appPath, "app-bin")
			buildCmd := exec.Command("go", "build", "-o", binPath, ".")
			buildCmd.Dir = appPath
			buildCmd.Stdout = os.Stdout
			buildCmd.Stderr = os.Stderr
			if err := buildCmd.Run(); err != nil {
				return nil, fmt.Errorf("failed to build Go app: %w", err)
			}
			args = []string{binPath}
		}

		// Node.js project? run dev
		hasNode := fileExists(filepath.Join(appPath, "package.json"))
		if hasNode && len(args) == 0 {
			var cmdName string
			var cmdArgs []string
			if fileExists(filepath.Join(appPath, "pnpm-lock.yaml")) {
				cmdName = "pnpm"
				cmdArgs = []string{"dev"}
			} else if fileExists(filepath.Join(appPath, "yarn.lock")) {
				cmdName = "yarn"
				cmdArgs = []string{"dev"}
			} else {
				cmdName = "npm"
				cmdArgs = []string{"run", "dev"}
			}
			portArg := "--port"
			if cmdName == "npm" {
				cmdArgs = append(cmdArgs, "--")
			}
			cmdArgs = append(cmdArgs, portArg, strconv.Itoa(appPort))
			args = append([]string{cmdName}, cmdArgs...)
		}

		if len(args) == 0 {
			return nil, fmt.Errorf("no run command provided for directory app: %s", appPath)
		}

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = appPath
		cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", appPort))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		cancel := func() {
			_ = cmd.Process.Signal(os.Interrupt)
			cmd.Process.Kill()
		}
		time.Sleep(10 * time.Second)
		return cancel, nil
	}

	// Case 2: File
	if stat.Mode()&0111 != 0 {
		// Executable binary
		cmd := exec.Command(appPath, args...)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", appPort))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		cancel := func() {
			_ = cmd.Process.Signal(os.Interrupt)
			cmd.Process.Kill()
		}
		time.Sleep(time.Second)
		return cancel, nil
	}

	// Non-executable file (e.g., index.php) → require run command after `--`
	if len(args) == 0 {
		return nil, fmt.Errorf("file %s is not executable, and no run command provided", appPath)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = filepath.Dir(appPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", appPort))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	cancel := func() {
		_ = cmd.Process.Signal(os.Interrupt)
		cmd.Process.Kill()
	}
	time.Sleep(10 * time.Second)
	return cancel, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	configDir := flag.String("config", "./config", "Config directory")
	appPath := flag.String("app", "", "Application path (dir or binary)")
	port := flag.Int("port", 3000, "Proxy port")
	appPort := flag.Int("app-port", 8080, "Application port")
	flag.Parse()

	cfg, err := loadConfig(*configDir)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cancelApp, err := startApp(*appPath, *appPort, flag.Args())
	if err != nil {
		log.Fatalf("failed to start app: %v", err)
	}
	defer cancelApp()

	app := fiber.New()

	// Apply basic auth middlewares
	for _, mw := range cfg.Middlewares {
		if mw.Type == "basicauth" {
			for _, route := range mw.Routes {
				app.Use(route, basicauth.New(basicauth.Config{
					Users: mw.Users,
				}))
			}
		}
	}

	// Middleware for headers applied AFTER proxy response
	app.Use(func(c *fiber.Ctx) error {
		err := c.Next() // run proxy first
		if err != nil {
			return err
		}

		for _, mw := range cfg.Middlewares {
			if mw.Type == "header" {
				for k, v := range mw.Set {
					c.Set(k, v)
				}
				for _, k := range mw.Remove {
					c.Request().Header.Del(k)
				}
			}
		}
		return nil
	})

	// Proxy the request to the application
	target := fmt.Sprintf("http://127.0.0.1:%d", *appPort)
	app.Use(proxy.Balancer(proxy.Config{
		Servers: []string{target},
	}))

	log.Printf("Middleware proxy running on :%d -> %s", *port, target)
	log.Fatal(app.Listen(fmt.Sprintf(":%d", *port)))
}
