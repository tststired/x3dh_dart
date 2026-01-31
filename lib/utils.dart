
import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';

Future<String> serializeKeyPair(SimpleKeyPair keyPair, String type) async {
	final pubKey = await keyPair.extractPublicKey();
	final privKey = await keyPair.extractPrivateKeyBytes();
	return jsonEncode({
	  'pubKey': base64Encode(pubKey.bytes),
	  'privKey': base64Encode(privKey),
	  'type': type,
	});
}

Future<SimpleKeyPair> deserializeKeyPair(String json) async {
  final Map<String, dynamic> map = jsonDecode(json);
  
  final pubKeyBytes = Uint8List.fromList(base64Decode(map['pubKey']));
  final privKeyBytes = Uint8List.fromList(base64Decode(map['privKey']));
  final typeString = map['type'] as String;

  KeyPairType keyPairType;
  switch (typeString) {
	case 'ed25519':
	  keyPairType = KeyPairType.ed25519;
	  break;
	case 'x25519':
	  keyPairType = KeyPairType.x25519;
	  break;
	default:
	  throw ArgumentError('Unsupported key pair type: $typeString');
  }

  return SimpleKeyPairData(
	privKeyBytes,
	publicKey: SimplePublicKey(pubKeyBytes, type: keyPairType),
	type: keyPairType,
  );
}

abstract class Serde<T> {
  Future<String> serialize();
  String serializePublic();
}