import 'package:test/test.dart';
import 'package:x3dh_dart/onetimeprekey.dart';

void main() {
  group('OneTimePreKey Tests', () {
    test('generate creates valid one-time prekey', () async {
      final oneTimePreKey = await OneTimePreKey.generate(42);
      
      expect(oneTimePreKey.id, equals(42));
      expect(oneTimePreKey.x2PubKey.bytes.length, equals(32));
      
      final privBytes = await oneTimePreKey.x2KeyPair.extractPrivateKeyBytes();
      expect(privBytes.length, equals(32));
    });

    test('generateBatch creates multiple keys with correct IDs', () async {
      final keys = await OneTimePreKey.generateBatch(5, startId: 10);
      
      expect(keys.length, equals(5));
      
      for (int i = 0; i < keys.length; i++) {
        expect(keys[i].id, equals(10 + i));
        expect(keys[i].x2PubKey.bytes.length, equals(32));
      }
      
      // Verify all keys are different
      for (int i = 0; i < keys.length; i++) {
        for (int j = i + 1; j < keys.length; j++) {
          expect(keys[i].x2PubKey.bytes, isNot(equals(keys[j].x2PubKey.bytes)));
        }
      }
    });

    test('generateBatch with default startId', () async {
      final keys = await OneTimePreKey.generateBatch(3);
      
      expect(keys.length, equals(3));
      expect(keys[0].id, equals(0));
      expect(keys[1].id, equals(1));
      expect(keys[2].id, equals(2));
    });

    test('serialize and deserialize work correctly', () async {
      final original = await OneTimePreKey.generate(123);
      final serialized = await original.serialize();
      
      expect(serialized, contains('id'));
      expect(serialized, contains('x2PubKey'));
      expect(serialized, contains('x2KeyPair'));
      
      final deserialized = await OneTimePreKey.deserialize(serialized);
      
      expect(deserialized.id, equals(original.id));
      expect(deserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      
      final origPriv = await original.x2KeyPair.extractPrivateKeyBytes();
      final deserPriv = await deserialized.x2KeyPair.extractPrivateKeyBytes();
      expect(deserPriv, equals(origPriv));
    });

    test('serialize and deserialize create equivalent objects', () async {
      final original = await OneTimePreKey.generate(999);
      final serialized = await original.serialize();
      final deserialized = await OneTimePreKey.deserialize(serialized);
      
      // Re-serialize
      final reSerialized = await deserialized.serialize();
      final reDeserialized = await OneTimePreKey.deserialize(reSerialized);
      
      // All should have identical key material
      expect(deserialized.id, equals(original.id));
      expect(deserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      expect(reDeserialized.id, equals(original.id));
      expect(reDeserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      
      // Serialized forms should be identical
      expect(reSerialized, equals(serialized));
    });

    test('serializePublic only contains public key', () async {
      final oneTimePreKey = await OneTimePreKey.generate(77);
      final publicSerialized = oneTimePreKey.serializePublic();
      
      expect(publicSerialized, contains('id'));
      expect(publicSerialized, contains('x2PubKey'));
      expect(publicSerialized, isNot(contains('KeyPair')));
      expect(publicSerialized, isNot(contains('privKey')));
    });

    test('different instances generate different keys', () async {
      final key1 = await OneTimePreKey.generate(1);
      final key2 = await OneTimePreKey.generate(1);
      
      // Same ID but different keys
      expect(key1.id, equals(key2.id));
      expect(key1.x2PubKey.bytes, isNot(equals(key2.x2PubKey.bytes)));
    });

    test('batch generation is efficient', () async {
      final stopwatch = Stopwatch()..start();
      final keys = await OneTimePreKey.generateBatch(100);
      stopwatch.stop();
      
      expect(keys.length, equals(100));
      // Should complete reasonably fast (less than 5 seconds)
      expect(stopwatch.elapsedMilliseconds, lessThan(5000));
    });
  });
}
