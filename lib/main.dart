import 'package:x3dh_dart/x3dh_dart.dart';
import 'package:x3dh_dart/identitykeypair.dart';
import 'package:x3dh_dart/signedprekey.dart';
import 'package:x3dh_dart/onetimeprekey.dart';
import 'package:x3dh_dart/prekeybundle.dart';
import 'dart:typed_data';
import 'dart:convert';
void main() async {


// Bob's setup (recipient)
final bobIdKey = await IdentityKeyPair.generate();
final bobSignedPreKey = await SignedPreKey.generate(bobIdKey);
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

print("Alice sent message: Hello Bob!");
print("Bob decrypted message: $decrypted");
// Both parties can now use the shared secret for encrypted communication
}