import 'package:test/test.dart';
import 'package:x3dh_dart/identitykeypair.dart';
import 'package:x3dh_dart/signedprekey.dart';

void main() {
  group('SignedPreKey Tests', () {
    test('generate creates valid signed prekey', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      expect(signedPreKey.id, equals(0));
      final now = DateTime.now().toUtc();
      final diff = now.difference(signedPreKey.tstamp).inSeconds;
      expect(diff, lessThan(60));
      expect(signedPreKey.x2PubKey.bytes.length, equals(32));
      expect(signedPreKey.sig.bytes.length, equals(64));
    });

    test('signature verification works', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      
      final isValid = await signedPreKey.verify();
      expect(isValid, isTrue);
    });

    test('serialize and deserialize work correctly', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final original = await SignedPreKey.generate(identityKeyPair);
      
      final serialized = await original.serialize();
      
      expect(serialized, contains('id'));
      expect(serialized, contains('tstamp'));
      expect(serialized, contains('x2PubKey'));
      expect(serialized, contains('x2KeyPair'));
      expect(serialized, contains('sig'));
      final deserialized = await SignedPreKey.deserialize(serialized, identityKeyPair);
      
      expect(deserialized.id, equals(original.id));
      expect(deserialized.tstamp, equals(original.tstamp));
      expect(deserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      expect(deserialized.sig.bytes, equals(original.sig.bytes));
      
      final isValid = await deserialized.verify();
      expect(isValid, isTrue);
    });

    test('multiple signed prekeys can be generated', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey1 = await SignedPreKey.generate(identityKeyPair);
      final signedPreKey2 = await SignedPreKey.generate(identityKeyPair);
      
      expect(signedPreKey1.x2PubKey.bytes, isNot(equals(signedPreKey2.x2PubKey.bytes)));
      expect(await signedPreKey1.verify(), isTrue);
      expect(await signedPreKey2.verify(), isTrue);
    });
  });

  group('Integration Tests', () {
    test('complete flow: generate identity, create signed prekey, serialize, deserialize, verify', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final identitySerialized = await identityKeyPair.serialize();
      final signedPreKeySerialized = await signedPreKey.serialize();
      final identityDeserialized = await IdentityKeyPair.deserialize(identitySerialized);
      final signedPreKeyDeserialized = await SignedPreKey.deserialize(signedPreKeySerialized, identityDeserialized);
      
      final isValid = await signedPreKeyDeserialized.verify();
      expect(isValid, isTrue);
      expect(identityDeserialized.x2PubKey.bytes, equals(identityKeyPair.x2PubKey.bytes));
      expect(identityDeserialized.edPubKey.bytes, equals(identityKeyPair.edPubKey.bytes));
      expect(signedPreKeyDeserialized.x2PubKey.bytes, equals(signedPreKey.x2PubKey.bytes));
    });
  });
}
