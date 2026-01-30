
// import 'dart:typed_data';
// import 'dart:convert';
// import 'package:cryptography/cryptography.dart';

// class X3DHResult {
//   final Uint8List sharedSecret;
//   final Uint8List associatedData;
//   final Uint8List ephemeralKey;
  
//   X3DHResult({ required this.sharedSecret, required this.associatedData, required this.ephemeralKey});
// }

// class X3DH {
//   /// Initiates the X3DH handshake from Alice's perspective.
//   /// 
//   /// Alice generates an ephemeral key pair and performs multiple DH exchanges
//   /// with Bob's prekey bundle to derive a shared secret.
//   /// 
//   /// Parameters:
//   /// - [aliceIdentityKeyPair]: Alice's long-term identity key pair
//   /// - [bobPreKeyBundle]: Bob's prekey bundle (received from server)
//   /// - [info]: Optional context information for KDF (default: "X3DH")
//   /// 
//   /// Returns: [X3DHResult] containing the shared secret and ephemeral public key
//   /// 
//   /// Throws: [Exception] if the signed prekey verification fails
//   /// 
//   static Future<X3DHResult> initiateHandshake({required IdentityKeyPair aliceIdentityKeyPair, required PreKeyBundle bobPreKeyBundle, String info = "X3DH-simplysteps"}) async {
//     final isValid = await bobPreKeyBundle.verifySignedPreKey();
//     if (!isValid) {
//       throw Exception('Failed to verify Bob\'s signed prekey signature');
//     }

//     final ephemeralKeyPair = await X25519().newKeyPair();
//     final ephemeralPubKey = (await ephemeralKeyPair.extractPublicKey()).bytes;
//     final ephemeralPrivKey = await ephemeralKeyPair.extractPrivateKeyBytes();

//     // Perform DH calculations
//     // DH1 = DH(IK_A, SPK_B)
//     final dh1 = await _performDH(
//       aliceIdentityKeyPair.x2PrivKey,
//       bobPreKeyBundle.signedPreKey.pubKey,
//     );

//     // DH2 = DH(EK_A, IK_B)
//     final dh2 = await _performDH(
//       ephemeralPrivKey,
//       bobPreKeyBundle.x2IdPubKey,
//     );

//     // DH3 = DH(EK_A, SPK_B)
//     final dh3 = await _performDH(
//       ephemeralPrivKey,
//       bobPreKeyBundle.signedPreKey.pubKey,
//     );

//     // DH4 = DH(EK_A, OPK_B) - only if one-time prekey is present
//     Uint8List? dh4;
//     if (bobPreKeyBundle.oneTimePreKey != null) {
//       dh4 = await _performDH(
//         ephemeralPrivKey,
//         bobPreKeyBundle.oneTimePreKey!.pubKey,
//       );
//     }

//     // Concatenate DH outputs: DH1 || DH2 || DH3 || DH4 (if present)
//     final dhOutputs = BytesBuilder();
//     dhOutputs.add(dh1);
//     dhOutputs.add(dh2);
//     dhOutputs.add(dh3);
//     if (dh4 != null) {
//       dhOutputs.add(dh4);
//     }

//     // Create associated data: IK_A || IK_B
//     final associatedData = BytesBuilder();
//     associatedData.add(aliceIdentityKeyPair.x2PubKey);
//     associatedData.add(bobPreKeyBundle.x2IdPubKey);

//     // Derive shared secret using HKDF
//     final sharedSecret = await _deriveSharedSecret(
//       dhOutputs.toBytes(),
//       associatedData.toBytes(),
//       info,
//     );

//     return X3DHResult(
//       sharedSecret: sharedSecret,
//       associatedData: associatedData.toBytes(),
//       ephemeralKey: Uint8List.fromList(ephemeralPubKey),
//     );
//   }

//   /// Completes the X3DH handshake from Bob's perspective.
//   /// 
//   /// Bob uses his identity key pair and prekeys to derive the same shared secret
//   /// that Alice computed.
//   /// 
//   /// Parameters:
//   /// - [bobIdentityKeyPair]: Bob's long-term identity key pair
//   /// - [bobSignedPreKey]: Bob's signed prekey that was in the bundle
//   /// - [bobOneTimePreKey]: Bob's one-time prekey (if used, otherwise null)
//   /// - [aliceIdentityPubKey]: Alice's identity public key
//   /// - [aliceEphemeralPubKey]: Alice's ephemeral public key (from handshake)
//   /// - [info]: Optional context information for KDF (default: "X3DH")
//   /// 
//   /// Returns: [X3DHResult] containing the shared secret
//   static Future<X3DHResult> completeHandshake({
//     required IdentityKeyPair bobIdentityKeyPair,
//     required SignedPreKey bobSignedPreKey,
//     required OneTimePreKey? bobOneTimePreKey,
//     required Uint8List aliceIdentityPubKey,
//     required Uint8List aliceEphemeralPubKey,
//     String info = "X3DH",
//   }) async {
//     // Perform DH calculations (same as Alice but with reversed roles)
//     // DH1 = DH(SPK_B, IK_A)
//     final dh1 = await _performDH(
//       bobSignedPreKey.privKey,
//       aliceIdentityPubKey,
//     );

//     // DH2 = DH(IK_B, EK_A)
//     final dh2 = await _performDH(
//       bobIdentityKeyPair.x2PrivKey,
//       aliceEphemeralPubKey,
//     );

//     // DH3 = DH(SPK_B, EK_A)
//     final dh3 = await _performDH(
//       bobSignedPreKey.privKey,
//       aliceEphemeralPubKey,
//     );

//     // DH4 = DH(OPK_B, EK_A) - only if one-time prekey was used
//     Uint8List? dh4;
//     if (bobOneTimePreKey != null) {
//       dh4 = await _performDH(
//         bobOneTimePreKey.privKey,
//         aliceEphemeralPubKey,
//       );
//     }

//     // Concatenate DH outputs: DH1 || DH2 || DH3 || DH4 (if present)
//     final dhOutputs = BytesBuilder();
//     dhOutputs.add(dh1);
//     dhOutputs.add(dh2);
//     dhOutputs.add(dh3);
//     if (dh4 != null) {
//       dhOutputs.add(dh4);
//     }

//     // Create associated data: IK_A || IK_B
//     final associatedData = BytesBuilder();
//     associatedData.add(aliceIdentityPubKey);
//     associatedData.add(bobIdentityKeyPair.x2PubKey);

//     // Derive shared secret using HKDF
//     final sharedSecret = await _deriveSharedSecret(
//       dhOutputs.toBytes(),
//       associatedData.toBytes(),
//       info,
//     );

//     return X3DHResult(
//       sharedSecret: sharedSecret,
//       associatedData: associatedData.toBytes(),
//       ephemeralKey: aliceEphemeralPubKey,
//     );
//   }

//   /// Performs X25519 Diffie-Hellman key exchange.
//   static Future<Uint8List> _performDH(List<int> privKey, List<int> bobPublicKey) async {
//     final privKeyPair = SimpleKeyPairData( privKey, 
// 	  publicKey: SimplePublicKey(List.filled(32, 0), type: KeyPairType.x25519), //dummy key 
//       type: KeyPairType.x25519,
//     );
    
//     final pubKey = SimplePublicKey(bobPublicKey, type: KeyPairType.x25519);
//     final sharedSecret = await X25519().sharedSecretKey(
//       keyPair: privKeyPair,
//       remotePublicKey: pubKey,
//     );
    
//     return Uint8List.fromList(await sharedSecret.extractBytes());
//   }

//   /// Derives the final shared secret using HKDF-SHA256.
//   /// 
//   /// Uses HKDF with:
//   /// - IKM (Input Key Material): concatenated DH outputs
//   /// - Salt: associated data (IK_A || IK_B)
//   /// - Info: context string (default "X3DH")
//   /// - Length: 32 bytes
//   static Future<Uint8List> _deriveSharedSecret(
//     Uint8List dhOutputs,
//     Uint8List associatedData,
//     String info,
//   ) async {
//     final hkdf = Hkdf(
//       hmac: Hmac(Sha256()),
//       outputLength: 32, // 256 bits
//     );

//     final derivedKey = await hkdf.deriveKey(
//       secretKey: SecretKey(dhOutputs),
//       nonce: associatedData,
//       info: utf8.encode(info),
//     );

//     return Uint8List.fromList(await derivedKey.extractBytes());
//   }
// }
