/*
Package main checks Redis instance for security vulnerabilities.

Checks:
	- AUTH is set.
	- CONFIG has been renamed.
	- Redis version is not vulnerable to CVE-2015-4335 (redis Lua sandbox escape and arbitrary code execution).

Flags:
	-localhost
		Verify that Redis is listening on the localhost interface ONLY, suppresses password check if so.
	-host <FQDN / IP address>
		Address of host running Redis. Default: 127.0.0.1
	-port <number>
		Port Redis is listening on. Default 6379
	-passfile <filename>
		Password file used to authenticate to redis. Default: password.txt
	-timeout <seconds>
		Duration in seconds when the initial connection or read attempt to the Redis instance times out.
	-help
		Short desctiption of the flags listed above.
		
		
	Copyright 2016, Yahoo Inc.
	Licensed under the terms of the Apache 2.0 License. Please see LICENSE file in project root for licensing terms.
*/

package main

import (
	"bufio"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHost = "127.0.0.1"
	defaultTimeout = 5
	defaultFile = "password.txt"
	defaultPort = "6379"
	localDefault = false
)

var (
	logger         = log.New(os.Stdout, "", log.LstdFlags)
	delay = defaultTimeout
	timeout        = &delay
	exitEnabled    = true
	
	configVulnerability	= false
	authVulnerability	= false
	luaVulnerability	= false

	// errNoInterfaces is the error returned when checkLocalhostOnly is unable to obtain the list of interfaces
	errNoInterfaces = errors.New("[error] Unable to get list of interfaces")

	// errExternalInterfaces is the error returned when localhost is specified, but Redis is listening on an external interface
	errExternalInterfaces = errors.New("[error] localhost only is specified, but Redis is listening on an external interface")

	// errEmptyPasswordFile is the error returnes when the password file is empty
	errEmptyPasswordFile = errors.New("[error] Empty password file")

	// errConfigCheck is the error returned when the Redis instance has not renamed the CONFIG command
	errConfigCheck = errors.New("[Security issue S1] Target has not renamed config")

	// errConfigUnknownError is the error returned when there was an unknown error verifying the CONFIG command
	errConfigUnknownError = errors.New("[error] Unknown error verifying CONFIG command")

	// errVersionCheck is the error returned when checkLuaCve is unable to parse the version number
	errVersionCheck = errors.New("[error] Version check failed")

	// errPasswordInvalid is the error returned when the password is invalid
	errPasswordInvalid = errors.New("[error] Target is using AUTH, password not valid")

	// errPasswordNotSet is the error returned when the Redis instance is not using passwords
	errPasswordNotSet = errors.New("[Security issue S2] Target is not using AUTH (Need to set AUTH password or bind to localhost only)")

	// errPasswordWhiteSpace is the error returned when the password in the password file contains whitespace
	errPasswordWhiteSpace = errors.New("[error] passwords containing whitespace are not valid")

	// errPasswordUnknownError is the error returned when an unknown error was encountered while verifying the AUTH command
	errPasswordUnknownError = errors.New("[error] Unknown error verifying AUTH command")

	// errLuaRce is the error returned when the version of Redis being tested is vulnerable to the CVE-2015-4335 Lua sandbox RCE vulnerability
	errLuaRce = errors.New("[Security issue S1] CVE-2015-4335 Lua sandbox RCE\n")
)

func main() {
	prefix, err := testHost()
	if len(prefix) != 0 {
		logger.Print(prefix)
	}
	if err != nil {
		logger.Print(err.Error())
		if exitEnabled {
			os.Exit(1)
		}
	}

}

func testHost() (string, error) {
	// Handle flags
	var localhostOnly = flag.Bool("localhost", localDefault, "Suppress password check if Redis is bound to localhost interface ONLY")
	var host = flag.String("host", defaultHost, "Address of host running Redis.")
	var port = flag.String("port", defaultPort, "Port Redis is listening on.")
	var passwordFileName = flag.String("passfile", defaultFile, "Password file used to authenticate to redis")
	timeout = flag.Int("timeout", defaultTimeout, "Connection timeout")
	flag.Parse()

	password := ""

	if *localhostOnly {
		*host = defaultHost
	}

	logger.Print("[info] Redis host:port = " + *host + ":" + *port)

	// Connect to Redis
	connection, err := net.DialTimeout("tcp", *host+":"+*port, time.Duration(*timeout)*time.Second)
	if err != nil {
		return "[error] Unable to connect to host: ", err
	}
	logger.Print("[info] Connected successfully to target")
	defer closeConnection(connection)

	connection.SetReadDeadline(time.Now().Add(time.Duration(*timeout) * time.Second))

	logger.Print("[info] Remote Address: " + connection.RemoteAddr().String())
	logger.Print("[info] Local Address : " + connection.LocalAddr().String())

	// Read password from file unless Redis is bound to localhost ONLY
	if *localhostOnly {
		_, err := checkLocalhostOnly(*port)
		if err != nil {
			return "[error] Check for Redis listening on localhost only: ", err
		}
	} else {
		passwordFile, err := os.Open(*passwordFileName)
		if err != nil {
			return "[error] Failed to open password file: ", err
		}
		defer passwordFile.Close()

		passwordScanner := bufio.NewScanner(passwordFile)
		passwordScanner.Scan()
		password = passwordScanner.Text()
		if err := passwordScanner.Err(); err != nil {
			return "[error] Failed to read password file", err
		}

		if len(password) == 0 {
			return "", errEmptyPasswordFile
		}
	}

	// Look for security issues
	if !*localhostOnly {
		p, err := checkPassword(connection, password)
		//Continue if password has not been set.
		if err == errPasswordNotSet {
			logger.Print(err.Error())
		} else {
			if err != nil {
				return p, err
			}
		}
		if len(p) != 0 {
			logger.Print(p)
		}
	}

	response, err := checkConfig(connection)
	if err != nil {
		//Continue if CONFIG has not been renamed.
		if err == errConfigCheck {
			logger.Print(err.Error())
		} else {
			return response, err
		}
	}

	response, err = verifyRedisVersion(connection)
	if err != nil {
		return response, err
	}
	
	printResults()
	
	return "[info] Verification complete.", nil
}

func printResults() {
	logger.Print("################################################")
	logger.Print("############# SUMMARY ##########################")
	if configVulnerability {
		logger.Print(errConfigCheck.Error())
	}
	if authVulnerability {
		logger.Print(errPasswordNotSet.Error())
	}
	if luaVulnerability {
		logger.Print(errLuaRce.Error())
	}
	if !(configVulnerability || authVulnerability || luaVulnerability) {
		logger.Print("No issues found!")
	}
	logger.Print("################################################")
}

// Verify that Redis is not listening on any external interface
func checkLocalhostOnly(port string) (bool, error) {
	logger.Print("[info] Checking to see if Redis is listening on localhost only.")

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, errNoInterfaces
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				externalConnection, err := net.DialTimeout("tcp", ipnet.IP.String()+":"+port, time.Duration(*timeout)*time.Second)
				if err != nil {
					logger.Printf("[info] Redis is not listening on: %s", ipnet.IP.String()+":"+port)
				} else {
					logger.Printf("[info] Redis is listening on: %s", ipnet.IP.String()+":"+port)
					externalConnection.Close()
					return false, errExternalInterfaces
				}

			}
		}
	}
	return true, nil
}

func closeConnection(connection net.Conn) {
	logger.Print("[info] Closing connection")
	_, err := connection.Write([]byte("QUIT\n"))
	if err != nil {
		logger.Print("[error] Error executing Redis QUIT command: %s", err.Error())
	}
	responseReader := bufio.NewScanner(connection)
	responseReader.Scan()
	connection.Close()
	return
}

func checkPassword(connection net.Conn, password string) (string, error) {
	logger.Print("[info] Verifying AUTH usage")
	_, err := connection.Write([]byte("AUTH " + password + "\n"))
	if err != nil {
		return "[error] Error executing Redis AUTH command: ", err
	}
	responseReader := bufio.NewScanner(connection)
	responseReader.Scan()
	out := responseReader.Text()
	if err := responseReader.Err(); err != nil {
		return "[error] Error reading AUTH response from Redis: ", err
	}
	if strings.Contains(out, "+OK") {
		return "[info] Target is using AUTH, password validated", nil
	}
	if strings.Contains(out, "invalid password") {
		return "", errPasswordInvalid
	}
	if strings.Contains(out, "wrong number of arguments") {
		return "", errPasswordWhiteSpace
	}
	if strings.Contains(out, "no password is set") {
		authVulnerability = true
		return "", errPasswordNotSet
	}
	return "", errPasswordUnknownError
}

func checkConfig(connection net.Conn) (string, error) {
	logger.Print("[info] Verifying CONFIG rename")

	_, err := connection.Write([]byte("CONFIG\n"))
	if err != nil {
		return "[error] Error executing Redis CONFIG command: ", err
	}

	responseReader := bufio.NewScanner(connection)
	responseReader.Scan()
	out := responseReader.Text()
	if err := responseReader.Err(); err != nil {
		return "[error] Error reading CONFIG response from Redis: ", err
	}
	if strings.Contains(out, "unknown command") {
		return "[info] Target has renamed CONFIG", nil
	}
	if strings.Contains(out, "wrong number of arguments") {
		configVulnerability = true
		return "", errConfigCheck
	}
	return "", errConfigUnknownError
}

// Returns map of Redis settings displayed in INFO command
func redisInfoCommand(connection net.Conn) (map[string]string, string, error) {
	var info = map[string]string{}
	KeyValueRegex := regexp.MustCompile("([^:]*):([^:]*)")

	_, err := connection.Write([]byte("INFO\n"))
	if err != nil {
		return nil, "[error] Error executing Redis command: ", err
	}

	responseReader := bufio.NewScanner(connection)
	for _, response, err := responseReader.Scan(), responseReader.Text(), responseReader.Err(); !strings.Contains(response, "# Keyspace"); _, response, err = responseReader.Scan(), responseReader.Text(), responseReader.Err() {
		if err != nil {
			return nil, "[error] Error reading INFO response from Redis: ", err
		}
		parseResult := KeyValueRegex.FindAllStringSubmatch(response, -1)
		if parseResult != nil {
			info[parseResult[0][1]] = parseResult[0][2]
		}
	}
	return info, "", nil
}

// CVE-2015-4335
func checkLuaCve(version string) (string, error) {
	versionRegex := regexp.MustCompile("([0-9]+).([0-9]+).([0-9]+)")
	parseResult := versionRegex.FindAllStringSubmatch(version, -1)
	if parseResult != nil {
		primary, _ := strconv.Atoi(parseResult[0][1])
		secondary, _ := strconv.Atoi(parseResult[0][2])
		tertiary, _ := strconv.Atoi(parseResult[0][3])

		if primary == 2 {
			if (secondary >= 8) && (tertiary >= 21) {
				logger.Printf("[info] Redis version %s OK", parseResult[0][0])
				return "", nil
			}
		} else if primary == 3 {
			if (secondary == 0) && (tertiary >= 2) {
				logger.Printf("[info] Redis version %s OK", parseResult[0][0])
				return "", nil
			}
		}
		luaVulnerability = true
		return "", errLuaRce
	}
	return "", errVersionCheck
}

func verifyRedisVersion(connection net.Conn) (string, error) {
	logger.Print("[info] Verifying version")

	response, errResp, err := redisInfoCommand(connection)
	if err != nil {
		return errResp, err
	}

	errResp, err = checkLuaCve(response["redis_version"])

	return errResp, err
}
