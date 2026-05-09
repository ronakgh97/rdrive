Tweaking with Network Protocol while building AWS s3 ***COMMUNIST VERSION***

Use docker [image](https://hub.docker.com/repository/docker/ronakgh97/rdrive/general)

```shell
docker pull ronakgh97/rdrive:latest (<60 mb)
docker run -d -p 3000:3000 -v rdrive-storage:/home/rdrive/.rdrive/storage --name rdrive ronakgh97/rdrive:latest
```

then you can use the CLI to push/pull files

```shell
rdrive push --file dummy.bin --protocol v1 --port 3000
Enter file key: ronak
1 a547a8a15a9b4ae890b8fe06bb542efe | pushed (2026-05-09 20:15:55) | pulled (never)
2 ac69860b5948400992116baca7f845f6 | pushed (2026-05-09 20:16:05) | pulled (never)
File already exists, overwrite? [N/0]: 0
Starting upload: dummy.bin (578.9375 mb)
File hash: 4ea1b5d5...
File ID: 0067f7174e754a9297f9ff35a6356ad2 - Time took: 1.5184643
````

```shell
rdrive pull --protocol v1 --port 3000                 
Enter file ID: a547a8a15a9b4ae890b8fe06bb542efe
Enter file key: ronak
Downloading: dummy.bin (578.9375 mb)
Saved to: .\dummy.bin
```

> Concurrent downloads are not supported yet (Non-trivial)

layering/CAS (WIP)

```shell
running 1 test
hash of old file: 7268156ca0497d7c7aad758656b2c080ec124eb1e06cbb5de4aa0f311219a7ee
hash of old layers:
Layer 0: hash=63c20485a34b72207119c02b0414ee86dd81fc49cb9f63b2b79715f38b57e8c9, offset=0, size=67108864
Layer 1: hash=03e09db653ef2e7b11f7654195ac4f53070b90d99b5c446c22fc973cd437c949, offset=67108864, size=67108864
Layer 2: hash=c3023dc7f6667e6bc37c4334a12d7d8e46803462a84fd0fe65870ce8fa58bc4d, offset=134217728, size=67108864
Layer 3: hash=05fb144065f7cb5b24dcca8d235122b1bd50f63afd4fb6422024e350f88b2ba1, offset=201326592, size=67108864
hash of reconstructed file: 7268156ca0497d7c7aad758656b2c080ec124eb1e06cbb5de4aa0f311219a7ee
hash of new layers:
Layer 0: hash=5a6111e3c550c1850e29d17fc237f89f15866f8b0569f59a6f628d63c54030d2, offset=0, size=67108864
Layer 1: hash=beba9d9c5428dabcd2c7c43db6bfa10d766b932bebc2dc0367c912392104b1e3, offset=67108864, size=67108864
Layer 2: hash=31974ed7ec7e866fda0a231f1e506c607a1b462f69d7186f6c0f50b3724c07d4, offset=134217728, size=67108864
Layer 3: hash=c0bbc29b7724a95af943188ac06be0a44485b52e36cba1a84c847c74792095b4, offset=201326592, size=67108864
Changed layers:
Layer 0: hash=63c20485a34b72207119c02b0414ee86dd81fc49cb9f63b2b79715f38b57e8c9, offset=0, size=67108864
Layer 1: hash=03e09db653ef2e7b11f7654195ac4f53070b90d99b5c446c22fc973cd437c949, offset=67108864, size=67108864
Layer 2: hash=c3023dc7f6667e6bc37c4334a12d7d8e46803462a84fd0fe65870ce8fa58bc4d, offset=134217728, size=67108864
Layer 3: hash=05fb144065f7cb5b24dcca8d235122b1bd50f63afd4fb6422024e350f88b2ba1, offset=201326592, size=67108864
test layer::experimental_layer_test ... ok
```

TODO

- Better Encryption for storage and metadata
- Better Bandwidth tracking and limits [DONE]
- Better Error handling and logging [DONE]
- Thread pool for better concurrency and resource management
- Better file management and cleanup strategies
- Authentication and access control
- Uhm...what else?
- Fix and improve the buffering and streaming for large files (diff hashing, chunking, chopping, etc.)
- More protocol features like file listing, metadata retrieval, more commands etc. [DONE]
- Graceful shutdown and cleanup
- Little bit client polish
- Protocol v2 meant to be use UDP, but skill issues...
- Encrypted share feature between clients (stateless relay server) without sharing the master key, maybe using some kind
  of temporary keys or
  something, idk
- Migrate to async architecture (TOKIO) [DONE]
- Too many repetitive code, need to refactor and clean up the codebase [DONE]
- Still some buffering issues, data gets stalls, does not flush properly [DONE]
- Multi-port support for better concurrency
- rsync support (rolling hashing, delta transfers, etc.) CDC `LAYERING like docker`
- Serialized headers, rm fragile parsing [DONE]
- Add proper user-space (multiple users)
- DO some CAS magic for better storage efficiency and deduplication
- Backup and restore features
- Fix the MASTER_KEY/Encrption redundancy

https://www.backblaze.com/docs/cloud-storage-about-backblaze-b2-cloud-storage

HIRE ME AS AN INTERN ***BLACKBLAZE*** 😭🌹