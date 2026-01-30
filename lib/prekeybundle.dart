
import 'dart:convert';
import 'package:x3dh_dart/signedprekey.dart';
import 'package:x3dh_dart/onetimeprekey.dart';
import 'package:x3dh_dart/identitykeypair.dart';


class PreKeyBundle {
  final IdentityKeyPair identityKeyPair;
  final SignedPreKey signedPreKey;
  final OneTimePreKey oneTimePreKey;

  PreKeyBundle({required this.identityKeyPair, required this.signedPreKey, required this.oneTimePreKey});
  
  String serializePublic() {
	return jsonEncode({
	  'identityKeyPair': jsonDecode(identityKeyPair.serializePublic()),
	  'signedPreKey': jsonDecode(signedPreKey.serializePublic()),
	  'oneTimePreKey': jsonDecode(oneTimePreKey.serializePublic()),
	});
  }

  Future<String> serialize() async {
	return jsonEncode({
		'identityKeyPair': jsonDecode(await identityKeyPair.serialize()),
		'signedPreKey': jsonDecode(await signedPreKey.serialize()),
		'oneTimePreKey': jsonDecode(await oneTimePreKey.serialize()),
	});
  }

  static Future<PreKeyBundle> deserialize(String json) async {
	final map = jsonDecode(json);
	
	// Re-encode the nested maps as JSON strings for the nested deserialize methods
	final identityKeyPair = await IdentityKeyPair.deserialize(jsonEncode(map['identityKeyPair']));
	final signedPreKey = await SignedPreKey.deserialize(jsonEncode(map['signedPreKey']), identityKeyPair);
	final oneTimePreKey = await OneTimePreKey.deserialize(jsonEncode(map['oneTimePreKey']));
	
	return PreKeyBundle(
	  identityKeyPair: identityKeyPair,
	  signedPreKey: signedPreKey,
	  oneTimePreKey: oneTimePreKey,
	);
  }
}