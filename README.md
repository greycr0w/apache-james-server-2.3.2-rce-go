# Apache James Server 2.3.2 Remote Command Execution Exploit

## Description
This is a Go implementation of a Remote Command Execution (RCE) exploit for Apache James Server 2.3.2.
Enhanced version of the original exploit by Jakub Palaczynski, Marcin Woloszyn, and Maciej Grabiec.

## Prerequisites
- Target must have default installation of Apache James Server 2.3.2 (details not specific)
- Default credentials (root/root) must be valid, else specify yours  
- With the default attack vector of using /etc/bash_completion.d, you need to wait for a user to SSH login for the payload to execute

## Exploit Details
1. Exploits the server through the /etc/bash_completion.d path
2. Writes a malicious file that gets sourced automatically on user login
3. File contains email headers and payload - headers cause harmless errors, payload executes
4. Requires user interaction (login) to trigger payload execution

> **Note**: Alternative exploitation methods like cron-based or no-interaction approaches could be
implemented by forking this code and altering the path traversal vulnerability to point to your choice of directory where files will be written to.