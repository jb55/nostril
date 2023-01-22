nostril(1)

# NAME

nostril - generate nostr events

# SYNPOSIS

*nostril* [OPTIONS...]

# DESCRIPTION

*nostril* is a tool that creates and signs nostr events.

# OPTIONS

*--content*
	The text contents of the note

*--dm* <hex pubkey>
	Create a direct message. This will create a kind-4 note with the
	contents encrypted>

*--envelope*
	Wrap the event with `["EVENT", ... ]` for easy relaying

*--kind* <number>
	Set the kind of the note

*--created-at* <unix timestamp>
	Set the created at. Optional, this is set automatically.

*--mine-pubkey*
	Mine a pubkey. This may or may not be cryptographically dubious.

*--pow* <difficulty>
	Number of leading 0 bits of the id the mine for proof-of-work.

*--tag* <key> <value>
	Add a tag with a single value

*-t*
	Shorthand for --tag t <hashtag>

*-p*
	Shorthand for --tag p <hex pubkey>

*-e*
	Shorthand for --tag e <note id>


# Examples

*Generate an event*

```
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
```

*Wrap event to send to a relay*

```
$ ./nostril --envelope --sec <key> --content "hello"
[ "EVENT",
{
	"id": "ed378d3fdda785c091e9311c6e6eeb075db349a163c5e38de95946f6013a8001",
	"pubkey": "fd3fdb0d0d8d6f9a7667b53211de8ae3c5246b79bdaf64ebac849d5148b5615f",
	"created_at": 1649948103,
	"kind": 1,
	"tags": [],
	"content": "hello",
	"sig": "9d9a49bbc66d4782030b24c71416965e790214d02a54ab132d960c2b02def0371c3d93e5a60a285c55e99721599d1332450731e2c6bb1114b96b591c6967f872"
} ]
```

*Send to a relay*

```
nostril --envelope --sec <key> --content "this is a message" | websocat wss://relay.damus.io
```

*Send a nip04 DM*

```
nostril --envelope --dm <pubkey> --sec <key> --content "this is a secret" | websocat wss://relay.damus.io
```

*Mine a pubkey*

```
nostril --mine-pubkey --pow <difficulty>
```

*Reply to an event. nip10 compliant, includes the `thread_id`*

```
./nostril --envelope --sec <key> --content "this is reply message" --tag e <thread_id> --tag e <note_id> | websocat wss://relay.damus.io
```
