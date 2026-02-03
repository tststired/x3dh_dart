# x3dh_dart

A minimized Dart implementation of the X3DH (Extended Triple Diffie-Hellman) key agreement protocol, enabling secure end-to-end encrypted communication without requiring both parties to be online simultaneously. Minus keytracking for onetimeprekeys/signedprekeys.

## What is X3DH?

X3DH is a key agreement protocol that establishes a shared secret between two parties who mutually authenticate each other based on public keys. It's designed for asynchronous messaging where one party may be offline during the key exchange.

The protocol provides:
- **Forward Secrecy**: Past communications remain secure even if keys are compromised
- **Cryptographic Deniability**: No long-term proof of participation
- **Asynchronous Operation**: Works when parties aren't simultaneously online

## Getting Started

Add this package to your `pubspec.yaml`:

```yaml
dependencies:
  x3dh_dart: ^0.0.1
  cryptography: ^2.9.0
```

## Usage

### Basic X3DH Handshake

```dart
import 'package:x3dh_dart/x3dh_dart.dart';

// Bob's setup (recipient)
final bobIdKey = await IdentityKeyPair.generate();
final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
final bobOneTimePreKey = await OneTimePreKey.generate(1);

final bobBundle = PreKeyBundle(
  identityKeyPair: bobIdKey,
  signedPreKey: bobSignedPreKey,
  oneTimePreKey: bobOneTimePreKey,
);

// Alice initiates handshake with an initial message
final aliceIdKey = await IdentityKeyPair.generate();
final aliceInitialMsg = await X3DH.initialMsg(
  aliceIdKeyPair: aliceIdKey,
  bobPreKeyBundle: bobBundle,
  initialMessage: "Hello Bob!",
);

// Alice can now send aliceInitialMsg to Bob (even if Bob is offline)

// Bob completes handshake when he comes online
final bobResult = await X3DH.completeHandshake(
  bobIdentityKeyPair: bobIdKey,
  bobSignedPreKey: bobSignedPreKey,
  bobOneTimePreKey: bobOneTimePreKey,
  aliceIdentityPubKey: Uint8List.fromList(aliceInitialMsg.aliceIdKeyPub.bytes),
  aliceEphemeralPubKey: Uint8List.fromList(aliceInitialMsg.aliceEpheKeyPub.bytes),
  initialMessage: aliceInitialMsg,
);

// Bob can decrypt the initial message
final decrypted = await X3DH.decrypt(
  sharedSecret: bobResult.sharedSecret,
  encryptMsg: aliceInitialMsg.initialCiphertext,
  assData: bobResult.assData,
);
// decrypted == "Hello Bob!"

// Both parties can now use the shared secret for encrypted communication
```

### Encrypting and Decrypting Messages

```dart
// After handshake, both parties have the same sharedSecret and assData

// Encrypt a message
final encrypted = await X3DH.encrypt(
  sharedSecret: sharedSecret,
  msg: "Secret message",
  assData: assData,
);

// Decrypt the message
final decrypted = await X3DH.decrypt(
  sharedSecret: sharedSecret,
  encryptMsg: encrypted,
  assData: assData,
);
```

### Safe Key Serialization

The library provides separate methods for serializing public and private keys:

```dart
final keyPair = await IdentityKeyPair.generate();

// For transmission over network (public keys only)
final publicJson = keyPair.serializePublic(); // Safe to transmit

// For secure local storage (includes private keys)
final fullJson = await keyPair.serialize(); // Keep this secret!

// Deserialize
final restored = await IdentityKeyPair.deserialize(fullJson);
```

### Generating One-Time Prekeys in Batch

```dart
// Generate 100 one-time prekeys efficiently
final oneTimeKeys = await OneTimePreKey.generateBatch(100);
```

## Architecture

### Key Components

1. **IdentityKeyPair**: Long-term identity keys (X25519 for DH, Ed25519 for signing)
2. **SignedPreKey**: Medium-term prekey signed by the identity key
3. **OneTimePreKey**: Single-use keys for enhanced forward secrecy
4. **PreKeyBundle**: Collection of public keys published by recipient
5. **X3DH**: The protocol implementation with `initialMsg` and `completeHandshake` methods
6. **X3DHResult**: Contains the derived shared secret and associated data
7. **X3DHInitialMessage**: Contains Alice's public keys and encrypted initial message

## Security Features

### Signature Verification
The implementation verifies that:
1. The signed prekey signature is cryptographically valid
2. The signature's public key matches the bundle's identity key (prevents key substitution attacks)

### Handshake Verification
When Bob completes the handshake, the implementation:
1. Computes the shared secret
2. Attempts to decrypt the initial message
3. **Aborts and throws an exception if decryption fails** (as per X3DH spec)

This ensures Bob only accepts the shared secret if the handshake was successful.

## Security Considerations

- **Never transmit private keys**: Use `serializePublic()` methods for transmission
- **Verify signatures**: Signature verification is automatic in `initialMsg()`
- **One-time key rotation**: Delete used one-time prekeys after use
- **Secure storage**: Encrypt private keys at rest
- **Context binding**: Use the `info` parameter for domain separation

## Implementation Details

- **Key Exchange**: X25519 elliptic curve Diffie-Hellman
- **Signatures**: Ed25519 for signing prekeys  
- **Key Derivation**: HKDF-SHA256 with 32-byte output
- **Encryption**: AES-256-GCM with authenticated encryption
- **Encoding**: Base64 for serialization

## Testing

Run the test suite:

```bash
dart test
```

The package includes comprehensive tests covering:
- Complete handshake flows
- Signature verification
- Identity key matching
- Handshake verification via decryption
- Multiple message exchanges
- Edge cases (empty messages, long messages, etc.)
- Security scenarios (tampered signatures, wrong keys, etc.)

## Additional Resources

- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Signal Protocol](https://signal.org/docs/)
- [Cryptography Package](https://pub.dev/packages/cryptography)

## License

See LICENSE file for details.
