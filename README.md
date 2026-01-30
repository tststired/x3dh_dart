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
final bobIdentity = await IdentityKeyPair.generate();
final bobSignedPreKey = await SignedPreKey.generate(1, bobIdentity);
final bobOneTimePreKey = await OneTimePreKey.generate(1);

// Bob publishes his prekey bundle
final bobBundle = PreKeyBundle(
  x2IdPubKey: bobIdentity.x2PubKey,
  edIdPubKey: bobIdentity.edPubKey,
  signedPreKey: bobSignedPreKey,
  oneTimePreKey: bobOneTimePreKey,
);

// Alice initiates handshake
final aliceIdentity = await IdentityKeyPair.generate();
final aliceResult = await X3DH.initiateHandshake(
  aliceIdentityKeyPair: aliceIdentity,
  bobPreKeyBundle: bobBundle,
);

// Bob completes handshake
final bobResult = await X3DH.completeHandshake(
  bobIdentityKeyPair: bobIdentity,
  bobSignedPreKey: bobSignedPreKey,
  bobOneTimePreKey: bobOneTimePreKey,
  aliceIdentityPubKey: aliceIdentity.x2PubKey,
  aliceEphemeralPubKey: aliceResult.ephemeralKey,
);

// Both parties now have the same shared secret!
assert(aliceResult.sharedSecret == bobResult.sharedSecret);
```

### Safe Key Serialization

The library provides separate methods for serializing public and private keys:

```dart
final keyPair = await IdentityKeyPair.generate();

// For transmission over network (public keys only)
final publicJson = keyPair.serializePublic(); // Safe to transmit

// For secure local storage (includes private keys)
final fullJson = keyPair.serialize(); // Keep this secret!
```

### Generating One-Time Prekeys in Batch

```dart
// Generate 100 one-time prekeys efficiently
final oneTimeKeys = await OneTimePreKey.generateBatch(100);
```

### Verifying Signed Prekeys

```dart
final bundle = PreKeyBundle.deserializePublic(receivedJson);

// Always verify before using
if (await bundle.verifySignedPreKey()) {
  // Bundle is authentic
  final result = await X3DH.initiateHandshake(...);
}
```

## Architecture

### Key Components

1. **IdentityKeyPair**: Long-term identity keys (X25519 + Ed25519)
2. **SignedPreKey**: Medium-term signed prekey for authentication
3. **OneTimePreKey**: Single-use keys for enhanced forward secrecy
4. **PreKeyBundle**: Collection of public keys published by recipient
5. **X3DH**: The protocol implementation with handshake methods
6. **X3DHResult**: Contains the derived shared secret and metadata

## Security Considerations
- **Never transmit private keys**: Use `serializePublic()` methods
- **Verify signatures**: Always call `verifySignedPreKey()` before handshake
- **One-time key rotation**: Delete used one-time prekeys
- **Secure storage**: Encrypt private keys at rest
- **Context binding**: Use the `info` parameter for domain separation

## Implementation Details

- **Key Exchange**: X25519 elliptic curve Diffie-Hellman
- **Signatures**: Ed25519 for signing prekeys
- **Key Derivation**: HKDF-SHA256 with 32-byte output
- **Encoding**: Base64 for serialization

## Additional Resources

- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Signal Protocol](https://signal.org/docs/)
- [Cryptography Package](https://pub.dev/packages/cryptography)

## Contributing

Contributions are welcome! Please ensure all tests pass and add new tests for any features.

## License

See LICENSE file for details.
