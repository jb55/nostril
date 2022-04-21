
# nostril

A cli util for creating nostr events

## Dependenices

`libsecp256k1` is the only dependency

## Usage

    usage: nostril [OPTIONS] --content <content>
    
      OPTIONS
    
          --dm <hex pubkey>               make an encrypted dm to said pubkey. sets kind and tags.
          --envelope                      wrap in ["EVENT",...] for easy relaying
          --kind <number>                 set kind
          --created-at <unix timestamp>   set a specific created-at time
          --sec <hex seckey>              set the secret key for signing, otherwise one will be randomly generated
          --pow <difficulty>              number of leading 0 bits of the id to mine
          --tag <key> <value>             add a tag
          -e <event_id>                   shorthand for --tag e <event_id>
          -p <pubkey>                     shorthand for --tag p <pubkey>

## Examples

Generate an event:

    $ ./nostril --sec <key> "this is a message"
    {
      "id": "b5c18a4aa21231a77b09748a5e623d9c2f853aed09653934b80a10b66a7225fa",
      "pubkey": "fd3fdb0d0d8d6f9a7667b53211de8ae3c5246b79bdaf64ebac849d5148b5615f",
      "created_at": 1649948031,
      "kind": 1,
      "tags": [],
      "content": "testing something again",
      "sig": "5122b2fc0d9a1f1ca134e4ab6fc1c9e5795e2d558cf24e3c7d8c4a35f889130eebcbd604602092a89c8a48469e88753e08dabb472610ac628ec9db3aa6c24672"
    }

Wrap event to send to a relay:

    $ ./nostril --envelope --sec <key> "hello"
    [
      "EVENT",
      {
        "id": "ed378d3fdda785c091e9311c6e6eeb075db349a163c5e38de95946f6013a8001",
        "pubkey": "fd3fdb0d0d8d6f9a7667b53211de8ae3c5246b79bdaf64ebac849d5148b5615f",
        "created_at": 1649948103,
        "kind": 1,
        "tags": [],
        "content": "hello",
        "sig": "9d9a49bbc66d4782030b24c71416965e790214d02a54ab132d960c2b02def0371c3d93e5a60a285c55e99721599d1332450731e2c6bb1114b96b591c6967f872"
      }
    ]

Send to a relay:

    $ ./nostril --envelope --sec <key> "this is a message" | websocat wss://nostr-pub.wellorder.net

Send a nip04 DM:

    $ ./nostril --envelope --dm <pubkey> --sec <key> "this is a secret" | websocat wss://nostr-pub.wellorder.net

