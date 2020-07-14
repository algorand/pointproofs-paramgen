The veccom-paramgen tool is intended to be used for the parameter generation MPC.

First, each participant will _register_ an "identity string", which is used to identify the party in the protocol and must be unique -- no two participants may register the same identity string. The string must contain or point to a signing public key (e.g., an ed25519 public key or a PGP key fingerprint) under which that participant's message will be signed. (The actual signing and verifying of messages will be handled by an external tool like gpg or signify.)

Then, the list of identity strings is sorted and published, along with a timetable for when each participant is expected to broadcast their message. (For instance, participant A must broadcast their message on Jan 1, participant B must broadcast their message on Jan 2, ...).
Additionally, the details of when/how the randomness beacon will be sampled are published. (For instance, if the last participant is to broadcast their message on July 1, "the beacon value will be the Q-value (block seed) in the next multiple-of-100000 Algorand block after midnight on July 2.") The randomness beacon needs to be publicly verifiable, hard to influence by any party, and not known until after the last participant broadcasts their message.

We assume participants have a means of broadcasting their messages and viewing all previous participants' messages. For instance, messages could be sent to a public mailing list, as was done in the Zcash powers-of-tau MPC.


### Initial parameters (zeroth participant)
Everyone can generate the "initial parameters" using the pointproofs-paramgen tool:

```
pointproofs-paramgen init /tmp/params.initial parameter_n
```

These "initial parameters" have no entropy; during the MPC each participant will in turn "mix in" their own entropy.
The `parameter_n` parameter should be announced in advance; it determines the maximum size of vectors that will be committed to -- larger `parameter_n` meanse larger generated parameters and slower generation.

### First participant

The first participant will take the initial parameters and "mix in their entropy":
```
veccom-paramgen evolve id_string /tmp/params.initial /tmp/params.1
```

where `id_string` is the identity string the participant registered. The participant will then sign `/tmp/params.1` with their signing key (using some separate tool) and broadcast this signed message.

Note that this implementation is not constant-time, so this command should not be run in a way that would allow an adversary to precisely measure its runtime.

## Finding the "latest good message"

In the honest-but-curious setting, participant `i` would work with participant `i-1`'s message. But in the malicious setting, participant `i-1` may output a bad message or no message at all. Participant `i` will iterate through the messages so far, verifying each one to determine the _latest good message_ as follows:

In the below pseudocode, 
* Let `id[j]` be the _j_'th participant's id string, with `j` ranging from 1 to `i-1`.
* Let `msg[0]` be the path to a file containing the initial params.
* Let `msg[j]` be the path to a file containing the _j_'th participant's message if participant _j_ sent a properly-signed message during their timeslot, where the signature is verified (using some separate tool) against the public key that participant registered. Otherwise, let `msg[j]` be "BAD".

```
latest_good_j := 0
for (j := 1; j < i; j++) {
	if (msg[j] != "BAD") && (`pointproofs-paramgen verify id[j] msg[latest_good_j] msg[j]` passes) {
		// Participant j's message is good
		latest_good_j = j
	}
}
return latest_good_j
```

In other words, the `pointproofs-paramgen` tool is used to verify each message in order against the most recent prior good message; if this verification passes and the message was properly signed and broadcast during the right timeslot, then the message is good.

## Participant `i`

In participant `i`'s timeslot, participant `i` will find the latest good message (message `j`), and then "mix their entropy" into the parameters in that message:

```
pointproofs-paramgen evolve id_string /tmp/params.j /tmp/params.i
```
where in this example `/tmp/params.j` contains the latest good message and `id_string` is the identity string participant `i` registered earlier.
Note that this implementation is not constant-time, so this command should not be run in a way that would allow an adversary to precisely measure its runtime.

The participant will then sign `/tmp/params.i` with their signing key (using some separate tool) and broadcast this signed message.

## Finalization
After the last participant broadcasts their message, everyone can (by following the steps for finding the "latest good message") find the last good message. 
At some predetermined time after the last participant's timeslot, entropy from the public randomness beacon is "mixed in" to the last good message, and this gives the final parameters. 
Everyone runs
```
pointproofs-paramgen finalize beacon_value /tmp/params.lastgood params.final
```
where `beacon_value` is the output of the randomness beacon. `params.final` will contain the final parameters.
Everyone can learn the set of participants that broadcast good messages -- they'll learn this as part of finding the last good message. As long as at least one of the participants in this set used good entropy and does not leak the entropy they used, the final parameters will be trustworthy.
