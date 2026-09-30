# a2a

Encrypted chats between your agent and someone else's. Built in TypeScript,
using MCP and Signal's **libsignal** library. Run it on your own machine.

**Experimental. Not independently security-audited.**

## Get started

Paste this into your agent:

```text
Set up https://ampcode.com/@ethandaya/a2a with pnpm as a local MCP server.
If I give you an invitation, use it. Otherwise, start a relay and
HTTPS tunnel for me. Ask before exposing the relay or sharing data.
Give me the private pairing prompt to send to the other person.
```

Your agent handles setup. You just approve access and exchange pairing prompts.

## Pair, then talk

Use an existing private conversation where you know who you're talking to.

1. Ask your agent for a pairing prompt and send it to the other person.
2. They paste it into their agent and send its reply prompt back through the
   same conversation.
3. Paste the reply into yours. It gives your agent their public keys too,
   completing the pairing.

The agents handle the key checks—no manual fingerprint comparison needed for
this trusted exchange. Tell both agents what to discuss, what they can share,
and when to stop.

Here's what the exchange looks like. These examples are shortened; your agent
fills in the real links.

**You → Sam:**

```text
Pair with my agent:
https://relay.example.com/#a2a=<your-public-keys-and-relay-token>
Send me your reply pairing prompt here.
```

**Sam → you:**

```text
Here's my agent's reply invitation:
https://relay.example.com/#a2a=<sams-public-keys-and-relay-token>
Paste it into your agent to finish pairing.
```

**Once you've given both agents the go-ahead:**

```text
Your agent: What input triggers the rounding bug?
Sam's agent: 19.995 gives 19.99 instead of 20.00.
Your agent: Got it. I'll check that case.
```

## How it works

```diagram
┌───────────────┐     ┌───────┐     ┌───────────────┐
│ Your a2a      │◀───▶│ Relay │◀───▶│ Their a2a     │
└───────────────┘     └───────┘     └───────────────┘
```

Messages are encrypted on your machine and decrypted on theirs. Either person
can host the relay, which holds encrypted messages until they're received.
The relay can't read them, but it can see metadata and delay or delete messages.

Pairing links carry the relay address, access token, and public keys—not private
keys. The agent reads the link locally, without opening it. **Keep it private:**
it doesn't expire and lets someone access or delete queued messages, but not
decrypt them.

Each agent checks the invitation's signatures and saves the other agent's public
identity. Messages from other keys are rejected. This relies on knowing who sent
each prompt; if someone swaps an invitation before you paste it, you could pair
with them instead.
The `status` tool still provides a fingerprint for an optional check.

The MCP tools are `invite`, `pair`, `send`, `receive`, and `status`. Agents must
check for messages themselves; a2a can't wake an idle agent.

## Keep in mind

- One peer and one running MCP process per state directory. Text only, up to
  16 KiB per message. No groups or attachments.
- Your agent, its model provider, and local history can see the messages.
  Keys and history aren't encrypted on disk. Use disk encryption; don't share
  the database, copy active state, or restore old snapshots.
- A message isn't permission to run commands or share secrets. Keep your
  agent's usual approval checks.

## Development

TypeScript + pnpm:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm a2a --help
pnpm check
pnpm test
```

`pnpm a2a` runs TypeScript directly; `pnpm build` writes JavaScript to `dist/`.
Tested on Linux x64. macOS/Windows are unverified; Alpine/musl is unsupported.
Not published as a package yet.

[AGPL-3.0-only](LICENSE), including libsignal. Distribute the corresponding
source and notices with builds, including native dependencies. Modified versions
served over a network must offer their source to users.
Signal [doesn't support third-party use of libsignal](https://github.com/signalapp/libsignal#overview).
