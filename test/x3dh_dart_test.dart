import 'dart:typed_data';
import 'dart:convert';
import 'package:test/test.dart';
import 'package:x3dh_dart/identitykeypair.dart';
import 'package:x3dh_dart/signedprekey.dart';
import 'package:x3dh_dart/onetimeprekey.dart';
import 'package:x3dh_dart/prekeybundle.dart';
import 'package:x3dh_dart/x3dh_dart.dart';

void main() {
  group('X3DH Protocol Tests', () {
    test('complete handshake between Alice and Bob', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey = await OneTimePreKey.generate(1);
      final bobBundle = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      final initialMessage = "Hello Bob, this is Alice!";
      final aliceInitialMsg = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle,
        initialMessage: initialMessage,
      );

      final serializedMsg = await aliceInitialMsg.serialize();

      final receivedMsg = X3DHInitialMessage.deserialize(serializedMsg);

      final bobResult = await X3DH.completeHandshake(
        bobIdentityKeyPair: bobIdKey,
        bobSignedPreKey: bobSignedPreKey,
        bobOneTimePreKey: bobOneTimePreKey,
        aliceIdentityPubKey: Uint8List.fromList(receivedMsg.aliceIdKeyPub.bytes),
        aliceEphemeralPubKey: Uint8List.fromList(receivedMsg.aliceEpheKeyPub.bytes),
        initialMessage: receivedMsg,
      );

      final decrypted = await X3DH.decrypt(
        sharedSecret: bobResult.sharedSecret,
        encryptMsg: receivedMsg.initialCiphertext,
        assData: bobResult.assData,
      );

      expect(decrypted, equals(initialMessage));
    });

    test('Alice and Bob can exchange multiple messages', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey = await OneTimePreKey.generate(1);
      final bobBundle = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      final aliceInitialMsg = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle,
        initialMessage: "Initial message",
      );

      final bobResult = await X3DH.completeHandshake(
        bobIdentityKeyPair: bobIdKey,
        bobSignedPreKey: bobSignedPreKey,
        bobOneTimePreKey: bobOneTimePreKey,
        aliceIdentityPubKey: Uint8List.fromList(aliceInitialMsg.aliceIdKeyPub.bytes),
        aliceEphemeralPubKey: Uint8List.fromList(aliceInitialMsg.aliceEpheKeyPub.bytes),
        initialMessage: aliceInitialMsg,
      );

      final sharedSecret = bobResult.sharedSecret;
      final assData = bobResult.assData;

      final messages = [
        "Message 1 from Alice",
        "Message 2 from Bob",
        "Message 3 from Alice with special chars: !@#\$%^&*()",
        "Message 4 with emoji 🚀",
      ];

      for (final msg in messages) {
        final encrypted = await X3DH.encrypt(
          sharedSecret: sharedSecret,
          msg: msg,
          assData: assData,
        );

        final decrypted = await X3DH.decrypt(
          sharedSecret: sharedSecret,
          encryptMsg: encrypted,
          assData: assData,
        );

        expect(decrypted, equals(msg));
      }
    });

    test('handshake fails with invalid signature', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey = await OneTimePreKey.generate(1);

      final serialized = await bobSignedPreKey.serialize();
      final Map<String, dynamic> data = jsonDecode(serialized);

      // Tamper with the signature bytes
      final sigBytes = base64Decode(data['sig']);
      sigBytes[0] ^= 0xFF; // Flip some bits
      sigBytes[10] ^= 0xFF;
      data['sig'] = base64Encode(sigBytes);

      // Deserialize with tampered signature
      final maliciousSignedPreKey = await SignedPreKey.deserialize(
        jsonEncode(data),
        bobIdKey,
      );

      final maliciousBundle = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: maliciousSignedPreKey,
        oneTimePreKey: bobOneTimePreKey,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      expect(
        () async => await X3DH.initialMsg(
          aliceIdKeyPair: aliceIdKey,
          bobPreKeyBundle: maliciousBundle,
          initialMessage: "This should fail",
        ),
        throwsException,
      );
    });

    test('handshake fails when identity key does not match signature', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey = await OneTimePreKey.generate(1);

      final attackerIdKey = await IdentityKeyPair.generate();

      // Attacker tries to use Bob's signed prekey with their own identity key
      final maliciousBundle = PreKeyBundle(
        identityKeyPair: attackerIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      expect(
        () async => await X3DH.initialMsg(
          aliceIdKeyPair: aliceIdKey,
          bobPreKeyBundle: maliciousBundle,
          initialMessage: "This should fail",
        ),
        throwsException,
      );
    });

    test('completeHandshake fails when initial ciphertext is tampered', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey = await OneTimePreKey.generate(1);
      final bobBundle = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      final aliceInitialMsg = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle,
        initialMessage: "Original message",
      );

      // Tamper with the ciphertext
      final serialized = await aliceInitialMsg.serialize();
      final Map<String, dynamic> data = jsonDecode(serialized);
      final cipherBytes = base64Decode(data['initialCiphertext']);
      cipherBytes[0] ^= 0xFF; // Flip some bits to corrupt the ciphertext
      data['initialCiphertext'] = base64Encode(cipherBytes);
      
      final tamperedMsg = X3DHInitialMessage.deserialize(jsonEncode(data));

      // Bob should reject the tampered message
      expect(
        () async => await X3DH.completeHandshake(
          bobIdentityKeyPair: bobIdKey,
          bobSignedPreKey: bobSignedPreKey,
          bobOneTimePreKey: bobOneTimePreKey,
          aliceIdentityPubKey: Uint8List.fromList(tamperedMsg.aliceIdKeyPub.bytes),
          aliceEphemeralPubKey: Uint8List.fromList(tamperedMsg.aliceEpheKeyPub.bytes),
          initialMessage: tamperedMsg,
        ),
        throwsException,
      );
    });

    test('decrypt fails with wrong shared secret', () async {
      final sharedSecret = Uint8List.fromList(List.filled(32, 0));
      final wrongSecret = Uint8List.fromList(List.filled(32, 1));
      final assData = Uint8List.fromList(List.filled(64, 0));

      final msg = "Secret message";
      final encrypted = await X3DH.encrypt(
        sharedSecret: sharedSecret,
        msg: msg,
        assData: assData,
      );

      expect(
        () async => await X3DH.decrypt(
          sharedSecret: wrongSecret,
          encryptMsg: encrypted,
          assData: assData,
        ),
        throwsA(anything),
      );
    });

    test('decrypt fails with wrong associated data', () async {
      final sharedSecret = Uint8List.fromList(List.filled(32, 0));
      final assData = Uint8List.fromList(List.filled(64, 0));
      final wrongAssData = Uint8List.fromList(List.filled(64, 1));

      final msg = "Secret message";
      final encrypted = await X3DH.encrypt(
        sharedSecret: sharedSecret,
        msg: msg,
        assData: assData,
      );

      expect(
        () async => await X3DH.decrypt(
          sharedSecret: sharedSecret,
          encryptMsg: encrypted,
          assData: wrongAssData,
        ),
        throwsA(anything),
      );
    });

    test('X3DHResult serialization', () async {
      final sharedSecret = Uint8List.fromList(List.filled(32, 42));
      final assData = Uint8List.fromList(List.filled(64, 99));

      final result = X3DHResult(
        sharedSecret: sharedSecret,
        assData: assData,
      );

      final serialized = await result.serialize();

      expect(serialized, contains('sharedSecret'));
      expect(serialized, contains('assData'));
    });

    test('X3DHInitialMessage serialization does not leak secrets', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey = await OneTimePreKey.generate(1);
      final bobBundle = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      final aliceInitialMsg = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle,
        initialMessage: "Test message",
      );

      final serialized = await aliceInitialMsg.serialize();

      expect(serialized, isNot(contains('sharedSecret')));
      expect(serialized, isNot(contains('assData')));

      expect(serialized, contains('aliceIdentityKey'));
      expect(serialized, contains('aliceEphemeralKey'));
      expect(serialized, contains('bobSignedPreKeyId'));
      expect(serialized, contains('bobOneTimePreKeyId'));
      expect(serialized, contains('initialCiphertext'));
    });

    test('different one-time prekeys produce different shared secrets', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final aliceIdKey = await IdentityKeyPair.generate();

      final bobOneTimePreKey1 = await OneTimePreKey.generate(1);
      final bobBundle1 = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey1,
      );

      final bobOneTimePreKey2 = await OneTimePreKey.generate(2);
      final bobBundle2 = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey2,
      );

      final msg1 = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle1,
        initialMessage: "Session 1",
      );

      final msg2 = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle2,
        initialMessage: "Session 2",
      );

      final bobResult1 = await X3DH.completeHandshake(
        bobIdentityKeyPair: bobIdKey,
        bobSignedPreKey: bobSignedPreKey,
        bobOneTimePreKey: bobOneTimePreKey1,
        aliceIdentityPubKey: Uint8List.fromList(msg1.aliceIdKeyPub.bytes),
        aliceEphemeralPubKey: Uint8List.fromList(msg1.aliceEpheKeyPub.bytes),
        initialMessage: msg1,
      );

      final bobResult2 = await X3DH.completeHandshake(
        bobIdentityKeyPair: bobIdKey,
        bobSignedPreKey: bobSignedPreKey,
        bobOneTimePreKey: bobOneTimePreKey2,
        aliceIdentityPubKey: Uint8List.fromList(msg2.aliceIdKeyPub.bytes),
        aliceEphemeralPubKey: Uint8List.fromList(msg2.aliceEpheKeyPub.bytes),
        initialMessage: msg2,
      );

      expect(bobResult1.sharedSecret, isNot(equals(bobResult2.sharedSecret)));
    });

    test('encrypt and decrypt empty message', () async {
      final sharedSecret = Uint8List.fromList(List.filled(32, 42));
      final assData = Uint8List.fromList(List.filled(64, 99));

      final msg = "";
      final encrypted = await X3DH.encrypt(
        sharedSecret: sharedSecret,
        msg: msg,
        assData: assData,
      );

      final decrypted = await X3DH.decrypt(
        sharedSecret: sharedSecret,
        encryptMsg: encrypted,
        assData: assData,
      );

      expect(decrypted, equals(msg));
    });

    test('encrypt and decrypt long message', () async {
      final sharedSecret = Uint8List.fromList(List.filled(32, 42));
      final assData = Uint8List.fromList(List.filled(64, 99));

      final msg = "A" * 10000;
      final encrypted = await X3DH.encrypt(
        sharedSecret: sharedSecret,
        msg: msg,
        assData: assData,
      );

      final decrypted = await X3DH.decrypt(
        sharedSecret: sharedSecret,
        encryptMsg: encrypted,
        assData: assData,
      );

      expect(decrypted, equals(msg));
    });

    test('custom info parameter changes derived key', () async {
      final bobIdKey = await IdentityKeyPair.generate();
      final bobSignedPreKey = await SignedPreKey.generate(bobIdKey, 0);
      final bobOneTimePreKey1 = await OneTimePreKey.generate(1);
      final bobOneTimePreKey2 = await OneTimePreKey.generate(2);
      final bobBundle1 = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey1,
      );
      final bobBundle2 = PreKeyBundle(
        identityKeyPair: bobIdKey,
        signedPreKey: bobSignedPreKey,
        oneTimePreKey: bobOneTimePreKey2,
      );

      final aliceIdKey = await IdentityKeyPair.generate();

      final msg1 = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle1,
        initialMessage: "Test",
        info: "custom-info-1",
      );

      final msg2 = await X3DH.initialMsg(
        aliceIdKeyPair: aliceIdKey,
        bobPreKeyBundle: bobBundle2,
        initialMessage: "Test",
        info: "custom-info-2",
      );

      final bobResult1 = await X3DH.completeHandshake(
        bobIdentityKeyPair: bobIdKey,
        bobSignedPreKey: bobSignedPreKey,
        bobOneTimePreKey: bobOneTimePreKey1,
        aliceIdentityPubKey: Uint8List.fromList(msg1.aliceIdKeyPub.bytes),
        aliceEphemeralPubKey: Uint8List.fromList(msg1.aliceEpheKeyPub.bytes),
        initialMessage: msg1,
        info: "custom-info-1",
      );

      final bobResult2 = await X3DH.completeHandshake(
        bobIdentityKeyPair: bobIdKey,
        bobSignedPreKey: bobSignedPreKey,
        bobOneTimePreKey: bobOneTimePreKey2,
        aliceIdentityPubKey: Uint8List.fromList(msg2.aliceIdKeyPub.bytes),
        aliceEphemeralPubKey: Uint8List.fromList(msg2.aliceEpheKeyPub.bytes),
        initialMessage: msg2,
        info: "custom-info-2",
      );

      expect(bobResult1.sharedSecret, isNot(equals(bobResult2.sharedSecret)));
    });
  });
}
