
import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:x3dh_dart/utils.dart';

class IdentityKeyPair {
  final SimpleKeyPair x2KeyPair;
  final SimpleKeyPair edKeyPair;
  late final SimplePublicKey x2PubKey;
  late final SimplePublicKey edPubKey;

  IdentityKeyPair._({required this.x2KeyPair, required this.edKeyPair});

  //why can't factories be async dart??
  static Future<IdentityKeyPair> generate() async {
    final x2KeyPair = await X25519().newKeyPair();
    final edKeyPair = await Ed25519().newKeyPair();

	final instance = IdentityKeyPair._(
      x2KeyPair: x2KeyPair,
      edKeyPair: edKeyPair,
    );
    instance.x2PubKey = await x2KeyPair.extractPublicKey();
    instance.edPubKey = await edKeyPair.extractPublicKey();
	return instance;
  }

  // don't upload this lmao
  Future<String> serialize() async {
    return jsonEncode({
      'x2PubKey': base64Encode(x2PubKey.bytes),
      'x2KeyPair': await serializeKeyPair(x2KeyPair, 'x25519'),
      'edPubKey': base64Encode(edPubKey.bytes),
      'edKeyPair': await serializeKeyPair(edKeyPair, 'ed25519'),
    });
  }

  // upload this one though
  String serializePublic() {
    return jsonEncode({
      'x2PubKey': base64Encode(x2PubKey.bytes),
      'edPubKey': base64Encode(edPubKey.bytes),
    });
  }
  
  static Future<IdentityKeyPair> deserialize(String json) async {
    final map = jsonDecode(json);
    final x2PubKey = Uint8List.fromList(base64Decode(map['x2PubKey']));
    final x2KeyPair = await deserializeKeyPair(map['x2KeyPair']);
    final edPubKey = Uint8List.fromList(base64Decode(map['edPubKey']));
    final edKeyPair = await deserializeKeyPair(map['edKeyPair']);

    final instance = IdentityKeyPair._(
      x2KeyPair: x2KeyPair,
      edKeyPair: edKeyPair,
    );
    
    instance.x2PubKey = SimplePublicKey(x2PubKey, type: KeyPairType.x25519);
    instance.edPubKey = SimplePublicKey(edPubKey, type: KeyPairType.ed25519);
    
    return instance;
  }
}
