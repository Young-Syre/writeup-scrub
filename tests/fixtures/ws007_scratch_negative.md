# Finished writeup

## Foothold

Enumerated SMB, found an AS-REP roastable account, cracked the ticket offline.

## Privilege Escalation

Abused the Backup Operators group to read the SAM and SYSTEM hives.

## Loot

Dumped domain hashes and verified access with evil-winrm.
