
import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:x3dh_dart/identitykeypair.dart';
import 'package:x3dh_dart/signedprekey.dart';
import 'package:x3dh_dart/onetimeprekey.dart';
import 'package:x3dh_dart/prekeybundle.dart';
import 'package:x3dh_dart/utils.dart';

class X3DHResult implements Serde<X3DHResult> {
  final Uint8List sharedSecret;
  final Uint8List assData;
  X3DHResult({ required this.sharedSecret, required this.assData});
  
  Future<X3DHResult> deserialize(String json) {
	throw UnimplementedError();
  }
  
  @override
  Future<String> serialize() {
	return Future.value(jsonEncode({
	  'sharedSecret': base64Encode(sharedSecret),
	  'assData': base64Encode(assData),
	}));
  }
  
  @override
  String serializePublic() {
	throw UnimplementedError();
  }
}

class X3DHInitialMessage implements Serde<X3DHInitialMessage> {
  final SimplePublicKey aliceIdKeyPub;
  final SimplePublicKey aliceEpheKeyPub;
  final int bobSignedPreKeyId;
  final int bobOneTimePreKeyId;
  final String initialCiphertext;
  
  X3DHInitialMessage({
    required this.aliceIdKeyPub,
	required this.aliceEpheKeyPub,
    required this.bobSignedPreKeyId,
    required this.bobOneTimePreKeyId,
    required this.initialCiphertext,
  });
  
  @override
  Future<String> serialize() async {
    return jsonEncode({
      'aliceIdentityKey': base64Encode(aliceIdKeyPub.bytes),
      'aliceEphemeralKey': base64Encode(aliceEpheKeyPub.bytes),
      'bobSignedPreKeyId': bobSignedPreKeyId,
      'bobOneTimePreKeyId': bobOneTimePreKeyId,
      'initialCiphertext': initialCiphertext,
    });
  }
  
  static X3DHInitialMessage deserialize(String json) {
    final map = jsonDecode(json);
    return X3DHInitialMessage(
      aliceIdKeyPub: SimplePublicKey(Uint8List.fromList(base64Decode(map['aliceIdentityKey'])), type: KeyPairType.x25519),
      aliceEpheKeyPub: SimplePublicKey(Uint8List.fromList(base64Decode(map['aliceEphemeralKey'])), type: KeyPairType.x25519),
      bobSignedPreKeyId: map['bobSignedPreKeyId'],
      bobOneTimePreKeyId: map['bobOneTimePreKeyId'],
      initialCiphertext: map['initialCiphertext'],
    );
  }
  
  @override
  String serializePublic() {
	throw UnimplementedError();
  }
}

class X3DH {
  //https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
  static Future<X3DHInitialMessage> initialMsg({
    required IdentityKeyPair aliceIdKeyPair, 
    required PreKeyBundle bobPreKeyBundle, 
    required String initialMessage,
    String info = "X3DH-simplysteps"
  }) async {
    final isValid = await bobPreKeyBundle.signedPreKey.verify();
    if (!isValid) {
      throw Exception('Failed to verify Bob\'s signed prekey signature');
    }

    // Verify the signature was made by the claimed identity key
    final sigPubKey = bobPreKeyBundle.signedPreKey.sig.publicKey as SimplePublicKey;
    final bundleIdPubKey = bobPreKeyBundle.identityKeyPair.edPubKey;
    if (sigPubKey.bytes.length != bundleIdPubKey.bytes.length) {
      throw Exception('Signed prekey signature does not match bundle identity key');
    }
    for (int i = 0; i < sigPubKey.bytes.length; i++) {
      if (sigPubKey.bytes[i] != bundleIdPubKey.bytes[i]) {
        throw Exception('Signed prekey signature does not match bundle identity key');
      }
    }

	// DHX is always Priv, Pub pairing
    final aliceEphKeyPair = await X25519().newKeyPair();
	final aliceIdKeyPriv = await aliceIdKeyPair.x2KeyPair.extractPrivateKeyBytes();
	final bobSignedPreKeyPub = bobPreKeyBundle.signedPreKey.x2PubKey.bytes;
	final aliceEphKeyPriv = await aliceEphKeyPair.extractPrivateKeyBytes();
	final bobIdKeyPub = bobPreKeyBundle.identityKeyPair.x2PubKey.bytes;
	final bobOneTimePreKeyPub = bobPreKeyBundle.oneTimePreKey.x2PubKey.bytes;
	final aliceIdKeyPub = aliceIdKeyPair.x2PubKey.bytes;

    // DH1 = DH(IK_A, SPK_B)
    final dh1 = await _diffiehill(aliceIdKeyPriv, bobSignedPreKeyPub);
    // DH2 = DH(EK_A, IK_B)
    final dh2 = await _diffiehill(aliceEphKeyPriv, bobIdKeyPub);
    // DH3 = DH(EK_A, SPK_B)
    final dh3 = await _diffiehill(aliceEphKeyPriv, bobSignedPreKeyPub);
	// DH4 = DH(EK_A, OPK_B)
    final dh4 = await _diffiehill(aliceEphKeyPriv, bobOneTimePreKeyPub);

    // SK = KDF(DH1 || DH2 || DH3 || DH4)
    final skey = BytesBuilder();
    skey.add(dh1);
    skey.add(dh2);
    skey.add(dh3);
    skey.add(dh4);

    // AD = Encode(IK_A || IK_B)
    final assData = BytesBuilder();
    assData.add(aliceIdKeyPub);
    assData.add(bobIdKeyPub);

    // Derive shared secret using HKDF
    final sharedSecret = await _hkdf(skey.toBytes(), assData.toBytes(), info);

    // Encrypt the initial message with the shared secret
    final initialCiphertext = await encrypt(
      sharedSecret: sharedSecret,
      msg: initialMessage,
      assData: assData.toBytes(),
    );

    return X3DHInitialMessage(
      aliceIdKeyPub: aliceIdKeyPair.x2PubKey,
      aliceEpheKeyPub: await aliceEphKeyPair.extractPublicKey(),
      bobSignedPreKeyId: bobPreKeyBundle.signedPreKey.id,
      bobOneTimePreKeyId: bobPreKeyBundle.oneTimePreKey.id,
      initialCiphertext: initialCiphertext,
    );
  }

  static Future<X3DHResult> completeHandshake({
	required IdentityKeyPair bobIdentityKeyPair,
	required SignedPreKey bobSignedPreKey,
	required OneTimePreKey bobOneTimePreKey,
	required Uint8List aliceIdentityPubKey,
	required Uint8List aliceEphemeralPubKey,
	required X3DHInitialMessage initialMessage, String info = "X3DH-simplysteps",
  }) async {

	final bobSignedPreKeyPriv = await bobSignedPreKey.x2KeyPair.extractPrivateKeyBytes();
	final bobIdKeyPriv = await bobIdentityKeyPair.x2KeyPair.extractPrivateKeyBytes();
	final bobOneTimePreKeyPriv = await bobOneTimePreKey.x2KeyPair.extractPrivateKeyBytes();
	
    // DH1 = DH(SPK_B, IK_A)
    final dh1 = await _diffiehill(bobSignedPreKeyPriv, aliceIdentityPubKey);
    // DH2 = DH(IK_B, EK_A)
    final dh2 = await _diffiehill(bobIdKeyPriv, aliceEphemeralPubKey);
    // DH3 = DH(SPK_B, EK_A)
    final dh3 = await _diffiehill(bobSignedPreKeyPriv, aliceEphemeralPubKey);
    // DH4 = DH(OPK_B, EK_A)
    final dh4 = await _diffiehill(bobOneTimePreKeyPriv, aliceEphemeralPubKey);

	// SK = KDF(DH1 || DH2 || DH3 || DH4)
    final skey = BytesBuilder();
    skey.add(dh1);
    skey.add(dh2);
    skey.add(dh3);
    skey.add(dh4);

	// AD = Encode(IK_A || IK_B)
    final assData = BytesBuilder();
    assData.add(aliceIdentityPubKey);
    assData.add(bobIdentityKeyPair.x2PubKey.bytes);

    final sharedSecret = await _hkdf(skey.toBytes(), assData.toBytes(), info);

    // Verify the handshake by attempting to decrypt the initial message
    //https://signal.org/docs/specifications/x3dh/#receiving-the-initial-messag
    try {
      await decrypt(
        sharedSecret: sharedSecret,
        encryptMsg: initialMessage.initialCiphertext,
        assData: assData.toBytes(),
      );
    } catch (e) {
      throw Exception('Failed to decrypt initial message: handshake verification failed');
    }

    return X3DHResult(
      sharedSecret: sharedSecret,
      assData: assData.toBytes(),
    );
  }

  static Future<Uint8List> _diffiehill(List<int> privKey, List<int> foreignPubKey) async {
    final privKeyPair = SimpleKeyPairData( privKey, 
	  publicKey: SimplePublicKey(List.filled(32, 0), type: KeyPairType.x25519), //dummy key 
      type: KeyPairType.x25519,
    );
    
    final pubKey = SimplePublicKey(foreignPubKey, type: KeyPairType.x25519);
    final sharedSecret = await X25519().sharedSecretKey(
      keyPair: privKeyPair,
      remotePublicKey: pubKey,
    );
    
    return Uint8List.fromList(await sharedSecret.extractBytes());
  }


  static Future<Uint8List> _hkdf(Uint8List dhOutputs, Uint8List assData, String info) async {
    final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
    
	final derivedKey = await hkdf.deriveKey(
      secretKey: SecretKey(dhOutputs),
      nonce: assData,
      info: utf8.encode(info),
    );

    return Uint8List.fromList(await derivedKey.extractBytes());
  }


  ///b64-encoded string containing nonce || ciphertext || mac
  static Future<String> encrypt({required Uint8List sharedSecret, required String msg, required Uint8List assData}) async {
    final skey = SecretKey(sharedSecret);
    final msgBytes = utf8.encode(msg);
    final secretBox = await AesGcm.with256bits().encrypt(msgBytes, secretKey: skey, aad: assData);

    final output = BytesBuilder();
    output.add(secretBox.nonce);
    output.add(secretBox.cipherText);
    output.add(secretBox.mac.bytes);

    return base64Encode(output.toBytes());
  }

  static Future<String> decrypt({required Uint8List sharedSecret, required String encryptMsg, required Uint8List assData}) async {
    final skey = SecretKey(sharedSecret);
    final encryptMsgBytes = base64Decode(encryptMsg);

    final nonce = encryptMsgBytes.sublist(0, 12);
    final mac = Mac(encryptMsgBytes.sublist(encryptMsgBytes.length - 16));
    final ciphertext = encryptMsgBytes.sublist(12, encryptMsgBytes.length - 16);
    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);

    final decrypted = await AesGcm.with256bits().decrypt(secretBox, secretKey: skey, aad: assData);
    return utf8.decode(decrypted);
  }
}
