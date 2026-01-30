import 'package:test/test.dart';
import 'package:x3dh_dart/identitykeypair.dart';

void main() {
  group('IdentityKeyPair Tests', () {
    test('generate creates valid key pairs', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      
      expect(identityKeyPair.x2PubKey.bytes.length, equals(32));
      expect(identityKeyPair.edPubKey.bytes.length, equals(32));
      
      final x2PrivBytes = await identityKeyPair.x2KeyPair.extractPrivateKeyBytes();
      final edPrivBytes = await identityKeyPair.edKeyPair.extractPrivateKeyBytes();
      expect(x2PrivBytes.length, equals(32));
      expect(edPrivBytes.length, equals(32));
    });

    test('serialize and deserialize work correctly', () async {
      final original = await IdentityKeyPair.generate();
      final serialized = await original.serialize();
      
      expect(serialized, isNotEmpty);
      expect(serialized, contains('x2PubKey'));
      expect(serialized, contains('edPubKey'));
      expect(serialized, contains('x2KeyPair'));
      expect(serialized, contains('edKeyPair'));
      
      final deserialized = await IdentityKeyPair.deserialize(serialized);
      
      expect(deserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      expect(deserialized.edPubKey.bytes, equals(original.edPubKey.bytes));
      
      final origX2Priv = await original.x2KeyPair.extractPrivateKeyBytes();
      final deserX2Priv = await deserialized.x2KeyPair.extractPrivateKeyBytes();
      expect(deserX2Priv, equals(origX2Priv));
      
      final origEdPriv = await original.edKeyPair.extractPrivateKeyBytes();
      final deserEdPriv = await deserialized.edKeyPair.extractPrivateKeyBytes();
      expect(deserEdPriv, equals(origEdPriv));
    });

    test('serialize and deserialize create functionally equivalent objects', () async {
      final original = await IdentityKeyPair.generate();
      final serialized = await original.serialize();
      final deserialized = await IdentityKeyPair.deserialize(serialized);
      final reSerialized = await deserialized.serialize();
      final reDeserialized = await IdentityKeyPair.deserialize(reSerialized);
      
      expect(deserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      expect(deserialized.edPubKey.bytes, equals(original.edPubKey.bytes));
      expect(reDeserialized.x2PubKey.bytes, equals(original.x2PubKey.bytes));
      expect(reDeserialized.edPubKey.bytes, equals(original.edPubKey.bytes));
      
      final origX2Priv = await original.x2KeyPair.extractPrivateKeyBytes();
      final reDeserX2Priv = await reDeserialized.x2KeyPair.extractPrivateKeyBytes();
      expect(reDeserX2Priv, equals(origX2Priv));
      
      final origEdPriv = await original.edKeyPair.extractPrivateKeyBytes();
      final reDeserEdPriv = await reDeserialized.edKeyPair.extractPrivateKeyBytes();
      expect(reDeserEdPriv, equals(origEdPriv));
      expect(reSerialized, equals(serialized));
    });

    test('serializePublic only contains public keys', () async {
      final identityKeyPair = await IdentityKeyPair.generate();
      final publicSerialized = identityKeyPair.serializePublic();
      
      expect(publicSerialized, contains('x2PubKey'));
      expect(publicSerialized, contains('edPubKey'));
      
      expect(publicSerialized, isNot(contains('KeyPair')));
      expect(publicSerialized, isNot(contains('privKey')));
    });

    test('different instances generate different keys', () async {
      final keyPair1 = await IdentityKeyPair.generate();
      final keyPair2 = await IdentityKeyPair.generate();
      
      expect(keyPair1.x2PubKey.bytes, isNot(equals(keyPair2.x2PubKey.bytes)));
      expect(keyPair1.edPubKey.bytes, isNot(equals(keyPair2.edPubKey.bytes)));
    });
  });

}
