import 'package:test/test.dart';
import 'package:x3dh_dart/identitykeypair.dart';
import 'package:x3dh_dart/signedprekey.dart';
import 'package:x3dh_dart/onetimeprekey.dart';
import 'package:x3dh_dart/prekeybundle.dart';

void main() {
  group('PreKeyBundle Tests', () {
    test('create prekey bundle with all components', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final oneTimePreKey = await OneTimePreKey.generate(1);
      
      final bundle = PreKeyBundle(
        identityKeyPair: identityKeyPair,
        signedPreKey: signedPreKey,
        oneTimePreKey: oneTimePreKey,
      );
      
      expect(bundle.identityKeyPair, equals(identityKeyPair));
      expect(bundle.signedPreKey, equals(signedPreKey));
      expect(bundle.oneTimePreKey, equals(oneTimePreKey));
    });

    test('serialize and deserialize work correctly', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final oneTimePreKey = await OneTimePreKey.generate(5);
      
      final original = PreKeyBundle(
        identityKeyPair: identityKeyPair,
        signedPreKey: signedPreKey,
        oneTimePreKey: oneTimePreKey,
      );
      
      final serialized = await original.serialize();
      
      expect(serialized, contains('identityKeyPair'));
      expect(serialized, contains('signedPreKey'));
      expect(serialized, contains('oneTimePreKey'));
      
      final deserialized = await PreKeyBundle.deserialize(serialized);
      
      // Verify identity key pair
      expect(deserialized.identityKeyPair.x2PubKey.bytes, 
             equals(original.identityKeyPair.x2PubKey.bytes));
      expect(deserialized.identityKeyPair.edPubKey.bytes, 
             equals(original.identityKeyPair.edPubKey.bytes));
      
      // Verify signed prekey
      expect(deserialized.signedPreKey.id, equals(original.signedPreKey.id));
      expect(deserialized.signedPreKey.x2PubKey.bytes, 
             equals(original.signedPreKey.x2PubKey.bytes));
      expect(deserialized.signedPreKey.sig.bytes, 
             equals(original.signedPreKey.sig.bytes));
      
      // Verify one-time prekey
      expect(deserialized.oneTimePreKey.id, equals(original.oneTimePreKey.id));
      expect(deserialized.oneTimePreKey.x2PubKey.bytes, 
             equals(original.oneTimePreKey.x2PubKey.bytes));
    });

    test('serialize and deserialize create equivalent objects', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final oneTimePreKey = await OneTimePreKey.generate(10);
      
      final original = PreKeyBundle(
        identityKeyPair: identityKeyPair,
        signedPreKey: signedPreKey,
        oneTimePreKey: oneTimePreKey,
      );
      
      final serialized = await original.serialize();
      final deserialized = await PreKeyBundle.deserialize(serialized);
      
      // Re-serialize
      final reSerialized = await deserialized.serialize();
      final reDeserialized = await PreKeyBundle.deserialize(reSerialized);
      
      // Verify all keys match through multiple round-trips
      expect(reDeserialized.identityKeyPair.x2PubKey.bytes, 
             equals(original.identityKeyPair.x2PubKey.bytes));
      expect(reDeserialized.signedPreKey.x2PubKey.bytes, 
             equals(original.signedPreKey.x2PubKey.bytes));
      expect(reDeserialized.oneTimePreKey.x2PubKey.bytes, 
             equals(original.oneTimePreKey.x2PubKey.bytes));
      
      // Serialized forms should be identical
      expect(reSerialized, equals(serialized));
    });

    test('serializePublic only contains public keys', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final oneTimePreKey = await OneTimePreKey.generate(15);
      
      final bundle = PreKeyBundle(
        identityKeyPair: identityKeyPair,
        signedPreKey: signedPreKey,
        oneTimePreKey: oneTimePreKey,
      );
      
      final publicSerialized = bundle.serializePublic();
      
      expect(publicSerialized, contains('identityKeyPair'));
      expect(publicSerialized, contains('signedPreKey'));
      expect(publicSerialized, contains('oneTimePreKey'));
      
      // Should not contain private key data (check for the nested key pair fields)
      expect(publicSerialized, isNot(contains('x2KeyPair')));
      expect(publicSerialized, isNot(contains('edKeyPair')));
      expect(publicSerialized, isNot(contains('privKey')));
    });

    test('deserialized bundle has valid signature', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final oneTimePreKey = await OneTimePreKey.generate(20);
      
      final original = PreKeyBundle(
        identityKeyPair: identityKeyPair,
        signedPreKey: signedPreKey,
        oneTimePreKey: oneTimePreKey,
      );
      
      final serialized = await original.serialize();
      final deserialized = await PreKeyBundle.deserialize(serialized);
      
      // Verify signature is still valid after deserialization
      final isValid = await deserialized.signedPreKey.verify();
      expect(isValid, isTrue);
    });

    test('multiple bundles with different one-time prekeys', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      
      final bundles = <PreKeyBundle>[];
      for (int i = 0; i < 5; i++) {
        final oneTimePreKey = await OneTimePreKey.generate(i);
        bundles.add(PreKeyBundle(
          identityKeyPair: identityKeyPair,
          signedPreKey: signedPreKey,
          oneTimePreKey: oneTimePreKey,
        ));
      }
      
      // All should share same identity and signed prekey
      for (int i = 1; i < bundles.length; i++) {
        expect(bundles[i].identityKeyPair.x2PubKey.bytes, 
               equals(bundles[0].identityKeyPair.x2PubKey.bytes));
        expect(bundles[i].signedPreKey.x2PubKey.bytes, 
               equals(bundles[0].signedPreKey.x2PubKey.bytes));
      }
      
      // But all should have different one-time prekeys
      for (int i = 0; i < bundles.length; i++) {
        for (int j = i + 1; j < bundles.length; j++) {
          expect(bundles[i].oneTimePreKey.x2PubKey.bytes, 
                 isNot(equals(bundles[j].oneTimePreKey.x2PubKey.bytes)));
        }
      }
    });

    test('complete workflow: generate, serialize, upload scenario', () async {
      // Step 1: Generate all keys locally
      final identityKeyPair = await IdentityKeyPair.generate();
      final signedPreKey = await SignedPreKey.generate(identityKeyPair);
      final oneTimePreKeys = await OneTimePreKey.generateBatch(10);
      
      // Step 2: Create bundle with first one-time prekey
      final bundle = PreKeyBundle(
        identityKeyPair: identityKeyPair,
        signedPreKey: signedPreKey,
        oneTimePreKey: oneTimePreKeys[0],
      );
      
      // Step 3: Serialize for upload (public only)
      final publicData = bundle.serializePublic();
      
      // Step 4: Store full bundle locally
      final privateData = await bundle.serialize();
      
      // Verify public data doesn't leak private keys (check for the nested key pair fields)
      expect(publicData, isNot(contains('x2KeyPair')));
      expect(publicData, isNot(contains('edKeyPair')));
      expect(publicData, isNot(contains('privKey')));
      
      // Verify private data contains everything
      expect(privateData, contains('x2KeyPair'));
      expect(privateData, contains('edKeyPair'));
      
      // Step 5: Restore from local storage
      final restored = await PreKeyBundle.deserialize(privateData);
      
      // Step 6: Verify restored bundle works
      final sigValid = await restored.signedPreKey.verify();
      expect(sigValid, isTrue);
      
      // Keys should match
      expect(restored.identityKeyPair.x2PubKey.bytes, 
             equals(identityKeyPair.x2PubKey.bytes));
    });
  });
}
