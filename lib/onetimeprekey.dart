import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:x3dh_dart/utils.dart';

class OneTimePreKey implements Serde<OneTimePreKey> {
  final int id;
  final SimpleKeyPair x2KeyPair;
  final SimplePublicKey x2PubKey;

  OneTimePreKey({
    required this.id,
    required this.x2PubKey,
    required this.x2KeyPair,
  });

  static Future<OneTimePreKey> generate(int id) async {
    final keyPair = await X25519().newKeyPair();

    return OneTimePreKey(
      id: id,
      x2PubKey: await keyPair.extractPublicKey(),
      x2KeyPair: keyPair,
    );
  }

  static Future<List<OneTimePreKey>> generateBatch(
    int count, {
    int startId = 0,
  }) async {
    final keys = <OneTimePreKey>[];
    for (int i = 0; i < count; i++) {
      keys.add(await generate(startId + i));
    }
    return keys;
  }

  @override
  Future<String> serialize() async {
    return jsonEncode({
      'id': id,
      'x2PubKey': base64Encode(x2PubKey.bytes),
      'x2KeyPair': await serializeKeyPair(x2KeyPair, 'x25519'),
    });
  }

  @override
  String serializePublic() {
	return jsonEncode({
	  'id': id,
	  'x2PubKey': base64Encode(x2PubKey.bytes),
	});
  }

  static Future<OneTimePreKey> deserialize(String json) async {
	final map = jsonDecode(json);
	final x2PubKey = Uint8List.fromList(base64Decode(map['x2PubKey']));
	final x2KeyPair = await deserializeKeyPair(map['x2KeyPair']);

	return OneTimePreKey(
	  id: map['id'],
	  x2PubKey: SimplePublicKey(x2PubKey, type: KeyPairType.x25519),
	  x2KeyPair: x2KeyPair,
	);
  }
}
