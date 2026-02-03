
import 'dart:typed_data';
import 'package:x3dh_dart/utils.dart';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:x3dh_dart/identitykeypair.dart';

class SignedPreKey implements Serde<SignedPreKey> {
  final int id;
  final Signature sig;
  final DateTime tstamp;
  final SimpleKeyPair x2KeyPair;
  final SimplePublicKey x2PubKey;

  SignedPreKey._({required this.x2KeyPair, required this.x2PubKey, required this.id, required this.sig, required this.tstamp});

  //change to flexible id, we're sacking forward secrecy we'll actually rotate this key now 
  static Future<SignedPreKey> generate(IdentityKeyPair identityKeyPair, int id) async {
    final keyPair = await X25519().newKeyPair();
    final pubKey = (await keyPair.extractPublicKey());

	// sign with idEdPrivkey
    final idEdPrivkey = SimpleKeyPairData( 
      await identityKeyPair.edKeyPair.extractPrivateKeyBytes(),
      publicKey: identityKeyPair.edPubKey,
      type: KeyPairType.ed25519,
    );

	//x2 keys can't sign thats why we need ed keys for signing im not implementing ed->x2 cba EdXDSA
	// there is a libsodium ffi binding
	//convertEd25519PublicToX25519Public 
    final sig = await Ed25519().sign(pubKey.bytes, keyPair: idEdPrivkey);

    return SignedPreKey._(
      id: id,
      sig: sig,
      tstamp: DateTime.now().toUtc(), 
	  x2KeyPair: keyPair,
      x2PubKey: pubKey
    );
  }

  Future<bool> verify() async {
    return await Ed25519().verify(x2PubKey.bytes, signature: sig);
  }

  bool shouldRotate({int maxAgeDays = 7}) {
    final now = DateTime.now().toUtc();
    final age = now.difference(tstamp);
    return age.inDays >= maxAgeDays;
  }

  @override
  Future<String> serialize() async {
	return jsonEncode({
	  'id': id,
	  'tstamp': tstamp.toIso8601String(),
	  'x2PubKey': base64Encode(x2PubKey.bytes),
	  'x2KeyPair': await serializeKeyPair(x2KeyPair, 'x25519'),
	  'sig': base64Encode(sig.bytes),
	});
  }

  @override
  String serializePublic() {
	return jsonEncode({
		'id': id,
		'tstamp': tstamp.toIso8601String(),
		'x2PubKey': base64Encode(x2PubKey.bytes),
		'sig': base64Encode(sig.bytes),
	});
  }
  

  static Future<SignedPreKey> deserialize(String json, IdentityKeyPair identityKeyPair) async {
	final Map<String, dynamic> map = jsonDecode(json);
	
	final id = map['id'] as int;
	final tstamp = DateTime.parse(map['tstamp'] as String);
	final x2PubKeyBytes = Uint8List.fromList(base64Decode(map['x2PubKey']));
	final x2KeyPair = await deserializeKeyPair(map['x2KeyPair']);
	final sigBytes = Uint8List.fromList(base64Decode(map['sig']));

	return SignedPreKey._(
	  id: id,
	  tstamp: tstamp,
	  x2PubKey: SimplePublicKey(x2PubKeyBytes, type: KeyPairType.x25519),
	  x2KeyPair: x2KeyPair,
	  sig: Signature(sigBytes, publicKey: identityKeyPair.edPubKey),
	);
  }

}