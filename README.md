Tweaking with Network Protocol & Security while building **State-of-the-art** Amazon s3 ***COMMUNIST VERSION***

`Goal: Protect servers from 'bad' users. Protect users from 'bad' servers`

**Features**

- file-system native database `directories are just mere hash table`
- super secure & decentralized e2e `(uses ed22519 key for identify & x25519 for encryption)`
- layering, delta transfer push/pull
- built-in custom TLS'ish, server secure even on raw ip port
- low memory usage, heavy in-place alloc thanks to global memory pool per connection
- backups, versioning, secure key rotation
- zero-trust architecture `(ssh like handshake)`
- fearless concurrency `(very little locks freeze)`

**Limitations**

- vulnerable to path injection `(maybe have some edge cases)` [SOLVED, Just use hash256]
- first connection not secure `(user must trust the server first)` [USER END ERROR, NOT CODE]
- no recovery keys
- compute waste for unauthorized client access, init handshake/exchange takes some time, but maybe minor issue, idk
- non-portable protocol, cross-lang support is a bit of chaos now

**How to set up?**

Use docker [image](https://hub.docker.com/repository/docker/ronakgh97/rdrive/general) then you can use the CLI to
auth/push/pull files

```shell
docker pull ronakgh97/rdrive:latest (<128 mb)
docker run -d -p 3000:3000 -v rdrive-storage:/home/rdrive/.rdrive/storage --name rdrive-node ronakgh97/rdrive:latest
```

```shell
# ssh into server or go inside container, 
# and create ~/.rdrive/authorized_keys/<hex public key> dir for whitelisting client 
# or just ENABLE_CLIENT_WHITELIST false

rdrive key # gen ed25519 keypair, does not overwrite until you do `-r` or `-a` for first init
Generated ed25519 keypair.
Public key (HEX):
2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b325677417945412f6b706e4e395748336c574a4d516457716d7448764f433363765a693344634154366b2b745a49686f2f733d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a
Make sure to whitelist your HEX public key on the server, If not already auth

mkdir ~/.rdrive/authorized_keys/2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b325677417945415447544c6b4a715432795039536775434268646c6b567966793345743248675850334d67316d644c6b75493d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a/

rdrive key -a # -a for init auth
Found existing keypair
Public key (HEX):
2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b325677417945412f6b706e4e395748336c574a4d516457716d7448764f433363765a693344634154366b2b745a49686f2f733d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a
Auth successfully

rdrive key -r # -r for rotate/sync key
Preview Public key (HEX):
2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b325677417945415447544c6b4a715432795039536775434268646c6b567966793345743248675850334d67316d644c6b75493d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a                    
Auth successfully
Key rotated/synced successfully
```

```shell
rdrive push --file dummy.bin --protocol v1 --port 3000
Enter file key: ronak
1 abc83897fc2c46e7941bb930e3715776 | pushed (2026-05-14 17:43:02) | pulled (never)
2 d6942ba17c8e4ecf941bf5eb24144036 | pushed (2026-05-14 17:43:11) | pulled (never)
Overwrite? [n/0]: 0
Starting upload: dummy.bin (578.9375 mb)
File hash: 4ea1b5d551d3876f74b6634c4dde1611a8000d798044268ea103736221e7378e
File ID: 9d6cd98c4503467faff3df10578e9e7c - Time took: 0.9695444
````

```shell
rdrive pull --protocol v1 --port 3000                 
Enter file ID: abc83897fc2c46e7941bb930e3715776
Enter file key: ronak
Downloading: dummy.bin (578.9375 mb)
Saved to: .\dummy.bin
```

Layering/Delta Transfer/CAS (WIP)

```shell
running 1 test
Hash of old file: 71a76fce0e402f2643078c01b1a82ddc6b647fa130c8647b0df8e327b6616e96
Layer metadata of old.tmp:
hash=d39aa5b5b22fd0ca18e073764b1a17c5c18d4e87f791d983c241624de1f53517, offset=0
hash=b4661b0652c6643b7dc4db85574af237f0c855ce5b19c167e30e41f0f161013d, offset=67108864
hash=16f4039ae20635e2e61db45257f2cccc9d122dcdfc7f32d89491565f5bc795a7, offset=134217728
hash=346104ebf6a91848949f8f5af8bff439e58dd75854abdcf731b278bd2ce5f7a1, offset=201326592
Hash of old file: cea79e99936ca4c3b85a144f8a542f631c4fd8a64b1368b967de57fe9252f1c2
Layer metadata of new.tmp:
hash=e40164c21c10e1f47c9eac7f8875796f6bbb3e2ec2a67f65911f0ce28acaae03, offset=0 # ONLY THIS LAYER CHANGED
hash=b4661b0652c6643b7dc4db85574af237f0c855ce5b19c167e30e41f0f161013d, offset=67108864
hash=16f4039ae20635e2e61db45257f2cccc9d122dcdfc7f32d89491565f5bc795a7, offset=134217728
hash=346104ebf6a91848949f8f5af8bff439e58dd75854abdcf731b278bd2ce5f7a1, offset=201326592
test layer::test_layering ... ok
```

TODO

- Better Encryption for storage and metadata
- Better Bandwidth tracking and limits [DONE]
- Better Error handling and logging [DONE]
- Thread pool for better concurrency and resource management
- Better file management and cleanup strategies [Partially DONE]
- Authentication and access control [Partially DONE]
- Fix and improve the buffering and streaming for large files (diff hashing, chunking, chopping, etc.)
- More protocol features like file listing, metadata retrieval, more commands etc. [DONE]
- Graceful shutdown and cleanup
- Little bit client polish, prefer 256 512 Hash over of raw hex, where can
- Protocol v2 meant to be use UDP, but skill issues...
- Encrypted share feature between clients (stateless relay server) without sharing the master key, maybe using some kind
  of temporary keys or
  something, idk [Partially DONE]
- Migrate to async architecture (TOKIO) [DONE]
- Too many repetitive code, need to refactor and clean up the codebase
- Still some buffering issues, data gets stalls, does not flush properly [DONE]
- Multi-port support for better concurrency
- rsync support (rolling hashing, delta transfers, etc.) CDC `LAYERING like docker`
- Serialized headers, rm fragile parsing [DONE]
- Add proper user-space (multiple users) [Partially DONE]
- DO some CAS magic for better storage efficiency and deduplication
- Backup and restore features
- Fix the MASTER_KEY/Encrption redundancy [Partially DONE]
- Proper secure protocol design, fuck TLS, SSL shit [Partially DONE]
- Portable cross-lang protocol
- Recoverable keys somehow?, better recover & key backups
- Global Memory Pool per connection [Partially DONE]
- Internal server error feedback or other similar
- Serialize overhead, some header does not that, fixed slice will do!!

https://www.backblaze.com/docs/cloud-storage-about-backblaze-b2-cloud-storage
https://www.rfc-editor.org/rfc/rfc8032
https://www.rfc-editor.org/rfc/rfc5869
https://www.openssh.org/

HIRE ME `BLACKBLAZE` 🥺😭🤧 🌹