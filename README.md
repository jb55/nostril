
# nostril

Cool nostr patch demo!

A cli util for creating nostr events

## Usage

    usage: nostril [OPTIONS]
    
      OPTIONS
    
          --content                       the content of the note
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

    $ ./nostril --sec <key> --content "this is a message"
    {
      "id": "da9c36bb8206e748cf136af2a43613a5ee113cb5906a09a8d3df5386039d53ab",
      "pubkey": "4f6fa8547cf2888415522918175ea0bc0eb473287c5bd7cc459ca440bdf87d97",
      "created_at": 1660750302,
      "kind": 1,
      "tags": [],
      "content": "this is a message",
      "sig": "3e4d7d93522e54f201a22944d4d37eb4505ef1cf91c278a3f7d312b772a6c6509d1e11f146d5a003265ae10411a20057bade2365501872d2f2f24219730eed87"
    }

Wrap event to send to a relay:

    $ ./nostril --envelope --sec <key> --content "hello"
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

    $ ./nostril --envelope --sec <key> --content "this is a message" | websocat wss://relay.damus.io

Send a nip04 DM:

    $ ./nostril --envelope --dm <pubkey> --sec <key> --content "this is a secret" | websocat wss://relay.damus.io

