Tweaking with Network Protocol & Security while building **State-of-the-art** Amazon s3 ***COMMUNIST VERSION***

**Features**

- file-system native database `directories are just mere hash table`
- super secure & decentralized e2e `(uses ed22519 key for identify & x25519 for encryption)`
- layering, delta transfer push/pull
- built-in custom x25519 keys encryption `TLS? what is that? cloudflare? who?`
- low memory usage, heavy in-place alloc thanks to global memory pool per connection
- backups, versioning, secure key rotation
- zero-trust architecture `(ssh like handshake)`
- fearless concurrency `(very little locks freeze)`

**Limitations**

- vulnerable to path injection `(maybe have some edge cases)` [SOLVED, just use hash256]
- first connection not secure `(user must trust the server first)` [USER END FAULT, NOT CODE]
- no recovery keys
- compute waste for unauthorized client access, init handshake/exchange takes some time, but maybe minor issue, idk
- non-portable protocol, cross-lang support is a bit of chaos now
- some protocols are not rate-limited as of now

**How to set up?**

Use docker [image](https://hub.docker.com/repository/docker/ronakgh97/rdrive/general) then you can use the CLI to
auth/push/pull files

```shell
docker pull ronakgh97/rdrive:latest (<125.26 MB)
docker run -d -p 3000:3000 -v rdrive-storage:/home/rdrive/.rdrive/storage --name rdrive-node ronakgh97/rdrive:latest
```

```shell
# start the server
rdrive-server serve --protocol v1 --port 3000                                 
[Server FP] 95800f880bb76e3c614f4a3daef6a6948990a2bde87406416895d77737fffbb4
[10:39:50][INFO] TCP Server (protocol v1) listening on 0.0.0.0:3000 (Max connections: 256)

# ssh into server or go inside container, 
# and create ~/.rdrive/authorized_keys/<sha256 public key_bytes hex> dir for whitelisting client 
# or just ENABLE_CLIENT_WHITELIST false

rdrive key # gen/log ed25519 pubkey, does NOT overwrite until you do `-r` if auth already or `-a` for first init
Found existing keypair
Public key (HEX SHA): d135e985fb19f343704bed31a3af6a7db91fee83bcfaadfb316ddf7cfa331635
Make sure to mkdir (whitelist) your SHA256 public key on the server ~/.rdrive/authorized_keys/

rdrive key -a
Found existing keypair
Public key (HEX SHA): d135e985fb19f343704bed31a3af6a7db91fee83bcfaadfb316ddf7cfa331635
Unknown Server IP: 127.0.0.1:3000
Server key FP: da480ff868f9e4ce9110abf289399131e246097bafb69006474370b7208bada8
Trust this server? [y/N]: y
Error: Auth failed: 403 - Client not authorized, please contact the admin, provider or ssh into the server

# whitelist the client public key on the server, then auth again
mkdir ~/.rdrive/authorized_keys\c8a5a04dba635ab9b60cc2ff1f19717e5b9c683bfeeacdfca73e5c23c76cf917

rdrive key -a # -a for init auth
Found existing keypair
Public key (HEX SHA): d135e985fb19f343704bed31a3af6a7db91fee83bcfaadfb316ddf7cfa331635
Auth successfully

rdrive key -r # -r for rotate/sync key
Preview change (HEX SHA)
> d135e985fb19f343704bed31a3af6a7db91fee83bcfaadfb316ddf7cfa331635
> dba1253bbe0f28705afdf6357aa55c44aaece05f3a56a75090a75cf5911a1fbe # does not SAVE, if sync fails
Auth successfully
Key rotated/synced successfully
```

```shell
rdrive push --file dummy.bin --protocol v1 --port 3000
Enter file key: ronak
1 4a43afa64e9342fc8320e63a43eb193b | pushed (2026-05-27 10:41:50) | pulled (never)
2 cf7aefc6b11d4ebd8eb87521125d3ef8 | pushed (2026-05-27 10:42:06) | pulled (never)
3 2fef22f7725d48f59fcd2e4f554854c6 | pushed (2026-05-27 10:42:56) | pulled (2026-05-27 10:43:34)
Overwrite? [n/0]: 1
Starting upload: dummy.bin (2048 mb)
File hash: b847e45da8d383833638cd57fcf7a223e0ef6c43ff2a9e12b511e6e99e30eacb
File ID: 4a43afa64e9342fc8320e63a43eb193b - Network_time: 1.4297787s

rdrive pull --protocol v1 --port 3000                 
Enter file ID: 2fef22f7725d48f59fcd2e4f554854c6
Enter file key: ronak
Downloading: dummy.bin (2048 mb)
Saved to: .\dummy.bin - Network_time: 0.0160485s
```

**TLS & Protocol perf**

```shell
rdrive perf --sample 1
Perf testing TLS Handshake, sampling for 60s
Port: 53911 Sample count: 8192                                                           
Samples: 8192
Success: 8192 Failed: 0
H/s: 372
p50: 2.59 ms
p95: 3.41 ms
p99: 4.70 ms

Perf testing encrypted protocol, sampling for 60s
Session Key: 05c9b5c66195d57aa6407807537e101da19fcaeca1d350db84989f4ec751e9c4
Sample: 644
Total payload: 4419MB
Server Time avg: 92ms # (~3ms in-flight-processing)
Network Time avg: 89ms (p50: 89 p95: 94 p99: 101)
```

**Layering/Delta Transfer**/CAS (WIP)

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

**How things are stored?**

```shell
.rdrive/
  authorized_keys/ # white_list & user key-space dir
    <sha256 public key1_bytes HEX>/ # im choosing hex over any key format for less friction and errors
      rot.history # for key rotation history, use case?
    <sha256 public key2_bytes HEX>/
      rot.history
    ...
    
  storage/
    <sha512 public key1 HEX>/ # user-space dir
      <sha256 file_key>/
        <sha256 file-id>/ # CAS/Layering and all that stuff
          e40164c21c10e...
          b4661b0652c66...
          ...
          metadata.json
    <sha512 public key2 HEX>/
      <sha256 file_key>/
        <sha256 file-id>/
          346104ebf6a9w...
          c9d122dcdfc70...
          ...
          metadata.json
    ...
            
  server/ # keep them here for now
    private_ed25519.key
    public_ed25519.key
```

> NOTE: This can be improved by introducing sharding & stuffs

TODO

- Better Encryption for storage and metadata
- Better Bandwidth tracking and limits [DONE]
- Better Error handling and logging [DONE]
- Thread pool for better concurrency and resource management [Partially DONE]
- Better file management and cleanup strategies [Partially DONE]
- Authentication and access control [Partially DONE]
- Fix and improve the buffering and streaming for large files (diff hashing, chunking, chopping, etc.)
- More protocol features like file listing, metadata retrieval, more commands etc. [DONE]
- Graceful shutdown and cleanup
- Little bit client polish, prefer 256 512 Hash over of raw hex OR PEM usage, where can [DONE]
- Protocol v2 meant to be use UDP, but skill issues...
- Encrypted share feature between clients (stateless relay server) without sharing the master key, maybe using some kind
  of temporary keys or
  something, IDK [Partially DONE]
- Migrate to async architecture (TOKIO) [DONE]
- Too many repetitive code, need to refactor and clean up the codebase
- Still some buffering issues, data gets stalls, does not flush properly [DONE]
- Multi-port support for better concurrency
- rsync support (rolling hashing, delta transfers, etc.) CDC `LAYERING like docker` [Partially DONE]
- Serialized headers, rm fragile parsing [DONE]
- Add proper user-space (multiple users) [DONE]
- DO some CAS magic for better storage efficiency and deduplication
- Backup and restore features
- Fix the MASTER_KEY/Encrption redundancy [DONE]
- Proper secure protocol design, fuck TLS, SSL shit [DONE]
- Portable cross-lang protocol
- Recoverable keys somehow?, better recover & key backups
- Global Memory Pool per connection [DONE]
- Internal server error feedback or other similar
- Serialize overhead, some header does not that, fixed slice will do!! [DONE]
- Rate limiting & basic guardrails [Partially DONE]

https://www.backblaze.com/docs/cloud-storage-about-backblaze-b2-cloud-storage
https://www.rfc-editor.org/rfc/rfc8032
https://www.rfc-editor.org/rfc/rfc5869
https://www.openssh.org/

HIRE ME `BLACKBLAZE` 🥺😭🤧 🌹