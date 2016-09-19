/*
	Copyright 2016, Yahoo Inc.
	Licensed under the terms of the Apache 2.0 License. Please see LICENSE file in project root for licensing terms.
*/

package main

import (
	"flag"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	rwLock = &sync.RWMutex{}
	exitWithoutInput = map[string]string{}
	configGood       = map[string]string{
		"CONFIG": "unknown command\n",
		"AUTH":   "+OK\n",
		"INFO":   "redis_version:3.0.2\n# Keyspace\n",
		"QUIT":   "",
	}
	configPasswordNotSet       = map[string]string{
		"CONFIG": "unknown command\n",
		"AUTH":   "no password is set\n",
		"INFO":   "redis_version:3.0.2\n# Keyspace\n",
		"QUIT":   "",
	}
	configNotRenamed = map[string]string{
		"CONFIG": "wrong number of arguments\n",
		"AUTH":   "+OK\n",
		"INFO":   "redis_version:3.0.2\n# Keyspace\n",
		"QUIT":   "",
	}
	configPassword = map[string]string{
		"AUTH": "invalid password\n",
		"QUIT":   "",
	}
	configConfiguration = map[string]string{
		"CONFIG": "wrong number of arguments\n",
		"QUIT":   "",
	}
	configVersion2821 = map[string]string{
		"CONFIG": "unknown command\n",
		"AUTH":   "+OK\n",
		"INFO":   "redis_version:2.8.21\n# Keyspace\n",
		"QUIT":   "",
	}
	configVersion2820 = map[string]string{
		"CONFIG": "unknown command\n",
		"AUTH":   "+OK\n",
		"INFO":   "redis_version:2.8.20\n# Keyspace\n",
		"QUIT":   "",
	}
	configVersion301 = map[string]string{
		"CONFIG": "unknown command\n",
		"AUTH":   "+OK\n",
		"INFO":   "redis_version:3.0.1\n# Keyspace\n",
		"QUIT":   "",
	}
	configInfoError = map[string]string{
		"CONFIG": "unknown command\n",
		"AUTH":   "+OK\n",
		"INFO":   "",
		"QUIT":   "",
	}
)

func TestNormal(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	done := make(chan bool, 1)
	go redisSimulator(":6379", configGood, t, done)
	<-done

	_, err := testHost()
	if err != nil {
		t.Errorf("TestNormal: got error=%s , wanted error=nil.", err.Error())
	}
	
	go redisSimulator(":6379", configGood, t, done)
	<-done

	os.Args = []string{"redischeck", "-passfile", "doesnotexist.txt"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	_, err = testHost()
	if err == nil {
		t.Errorf("TestNormal: got error=nil, wanted error on non-existent password file doesnotexist.txt.")
	} else {
		logger.Print(err.Error())
	}
	
	

}

// There should bo no error is config is not renamed.
func TestPasswordNotSet(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configPasswordNotSet, t, done)
	<-done

	_, err := testHost()
	if err != nil {
		t.Errorf("TestConfigNotRenamed: got error=%s , wanted error=nil.", err.Error())
	}
}

// There should bo no error is config is not renamed.
func TestConfigNotRenamed(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configNotRenamed, t, done)
	<-done

	_, err := testHost()
	if err != nil {
		t.Errorf("TestConfigNotRenamed: got error=%s , wanted error=nil.", err.Error())
	}
}

func TestLocalhostErr(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck", "-localhost"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configGood, t, done)
	<-done

	_, err := testHost()
	if err != errExternalInterfaces {
		t.Errorf("TestNormal: got nil , wanted errExternalInterfaces.")
	}
}

func TestVersion2821(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configVersion2821, t, done)
	<-done

	_, err := testHost()
	if err != nil {
		t.Errorf("TestVersion2821: got error=%s , wanted error=nil.", err.Error())
	}
}

func TestVersion2820(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configVersion2820, t, done)
	<-done

	_, err := testHost()
	if err != nil {
		if err != errLuaRce {
			t.Errorf("TestVersion2820: got error=%s , wanted error=nil.", err.Error())
		}
	} else {
		t.Errorf("TestVersion2820: got no error , wanted errLuaRce.")
	}
}

func TestVersion301(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configVersion301, t, done)
	<-done

	_, err := testHost()
	if err != nil {
		if err != errLuaRce {
			t.Errorf("TestVersion301: got error=%s , wanted error=nil.", err.Error())
		}
	} else {
		t.Errorf("TestVersion301: got no error , wanted errLuaRce.")
	}
}

func TestVerifyRedisVersion(t *testing.T) {

	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configInfoError, t, done)
	<-done

	// Connect to Redis
	connection, err := net.DialTimeout("tcp", "localhost:6379", time.Duration(1)*time.Second)
	if err != nil {
		t.Errorf("TestVerifyRedisVersion: Unable to connect to simulator: %s", err.Error())
		return
	}
	
	connection.SetReadDeadline(time.Now().Add(time.Duration(1) * time.Second))
	_, err= verifyRedisVersion(connection)
	if err == nil {
		t.Errorf("TestVerifyRedisVersion: got no error, wanted timeout error.")
	} else {
		_, found := err.(*net.OpError)
		if !found {
			t.Errorf("TestVerifyRedisVersion: got %s, wanted timeout error.", err.Error())
		} else {
			if !(err.(*net.OpError)).Timeout() {
				t.Errorf("TestVerifyRedisVersion: got net.OpError %s, wanted timeout error.", err.Error())
			}
		}
	}

	// Write error - redisSimulator has exited.
	connection.Close()

	connection.SetReadDeadline(time.Now().Add(time.Duration(1) * time.Second))
	_, err= verifyRedisVersion(connection)
	if err == nil {
		t.Errorf("TestPasswordErrors: got no error , wanted i/o error.")
	}

}

func TestCheckLocalhostOnly(t *testing.T) {

	exitEnabled = false

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", exitWithoutInput, t, done)
	<-done

	if result, err := checkLocalhostOnly("6379"); (result) || (err == nil) {
		t.Errorf("checkLocalhostOnly(6379) = %v, want false, err = %v, want non-nil", result, err)
	}

	// Can checkLocalhostOnly(...) detect when there are no non-localhost port?
	if result, err := checkLocalhostOnly("6379"); (!result) || (err != nil) {
		t.Errorf("checkLocalhostOnly(6379) = %v, want true, err = %v, want nil", result, err)
	}

}

func TestPasswordErrors(t *testing.T) {
	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configPassword, t, done)
	<-done

	// Connect to Redis
	connection, err := net.DialTimeout("tcp", "localhost:6379", time.Duration(1)*time.Second)
	if err != nil {
		t.Errorf("TestPasswordErrors: Unable to connect to simulator: %s", err.Error())
	}

	_, err = checkPassword(connection, "test")
	if err != errPasswordInvalid {
		t.Errorf("TestPasswordErrors: got no error , wanted errPasswordInvalid.")
	}

	update(configPassword, "AUTH", "wrong number of arguments\n")
	_, err = checkPassword(connection, "test")
	if err != errPasswordWhiteSpace {
		t.Errorf("TestPasswordErrors: got no error , wanted errPasswordWhiteSpace.")
	}

	update(configPassword, "AUTH", "no password is set\n")
	_, err = checkPassword(connection, "test")
	if err != errPasswordNotSet {
		t.Errorf("TestPasswordErrors: got no error , wanted errPasswordNotSet.")
	}

	update(configPassword, "AUTH", "unknown error\n")
	_, err = checkPassword(connection, "test")
	if err != errPasswordUnknownError {
		t.Errorf("TestPasswordErrors: got no error , wanted errPasswordUnknownError.")
	}

	// Read error
	update(configPassword, "AUTH", "")
	connection.SetReadDeadline(time.Now().Add(time.Duration(1) * time.Second))
	_, err = checkPassword(connection, "test")
	if err == nil {
		t.Errorf("TestPasswordErrors: got no error , wanted i/o error.")
	}

	// Write error - redisSimulator has exited.
	connection.Close()
	_, err = checkPassword(connection, "test")
	if err == nil {
		t.Errorf("TestPasswordErrors: got no error , wanted i/o error.")
	}
}


func TestCheckLuaCve(t *testing.T) {
	
	_, err:= checkLuaCve(".0.2")
	if err != errVersionCheck {
		t.Errorf("TestcheckLuaCve: got no error , wanted errVersionCheck.")
	}


}

func TestConfigErrors(t *testing.T) {
	exitEnabled = false
	os.Args = []string{"redischeck"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Can checkLocalhostOnly(...) detect when something is listening on a non-localhost port?
	done := make(chan bool, 1)
	go redisSimulator(":6379", configConfiguration, t, done)
	<-done

	// Connect to Redis
	connection, err := net.DialTimeout("tcp", "localhost:6379", time.Duration(1)*time.Second)
	if err != nil {
		t.Errorf("TestConfigErrors: Unable to connect to simulator: %s", err.Error())
	}

	_, err = checkConfig(connection)
	if err != errConfigCheck {
		t.Errorf("TestConfigErrors: got no error , wanted errConfigCheck.")
	}

	update(configConfiguration, "CONFIG", "unknown error\n")
	_, err = checkConfig(connection)
	if err != errConfigUnknownError {
		t.Errorf("TestConfigErrors: got no error , wanted errConfigUnknownError.")
	}

	// Read error
	update(configConfiguration, "CONFIG", "")
	connection.SetReadDeadline(time.Now().Add(time.Duration(1) * time.Second))
	_, err = checkConfig(connection)
	if err == nil {
		t.Errorf("TestConfigErrors: got no error , wanted i/o error.")
	}

	// Write error - redisSimulator has exited.
	connection.Close()
	_, err = checkConfig(connection)
	if err == nil {
		t.Errorf("TestConfigErrors: got no error , wanted i/o error.")
	}
}

func redisSimulator(address string, actions map[string]string, t *testing.T, done chan bool) {
	data := make([]byte, 4096)

	ln, err := net.Listen("tcp", address)
	if err != nil {
		logger.Printf("redisSimulator: got error=%v(%T),  net.OpError.Err= %v(%T), wanted error=nil in net.Listen(\"tcp\", %s)", err, err.(*net.OpError).Err, err, address)
		done <- true
		return
	}
	defer ln.Close()

	done <- true

	conn, err := ln.Accept()
	if err != nil {
		logger.Printf("listenAndQuit: got error=%v , wanted error=nil in ln.Accept() on %s", err, address)
		return
	}

	//if the map is empty, don't wait for input
	if len(actions) == 0 {
		return
	}

	for {
		n, err := conn.Read(data)
		if err != nil {
			// Anything other than EOF is an error
			if err != io.EOF {
				logger.Printf("listenAndQuit: error reading data: %s", err.Error())
			}
			return
		}
		input := string(data[:n])

		for i := range actions {
			if strings.Contains(input, i) {

				// If response is empty, return to cause a i/o timeout
				if len(get( actions, i)) == 0 {
					return
				}

				_, err := conn.Write([]byte(get(actions, i)))
				if err != nil {
					// send an error if it's encountered
					logger.Printf("\nlistenAndQuit: error writing data: %s", err.Error())
					return
				}
			}
		}
	}

}

// Coordinate writes between test function and Redis simulator
func update(config map[string]string, key string, value string) {
	rwLock.Lock()
	config[key] = value
	rwLock.Unlock()
}

// Coordinate reads between test function and Redis simulator
func get(config map[string]string, key string) (string) {
	rwLock.RLock()
	value := config[key]
	rwLock.RUnlock()
	return value
}
