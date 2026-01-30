import 'package:x3dh_dart/x3dh_dart.dart';
import 'dart:convert';

void main() async {
//   print('=== X3DH Protocol Example ===\n');

//   // --- Bob's Setup (Server-side) ---
//   print('1. Bob generates his long-term identity keys...');
//   final bobIdentityKeyPair = await IdentityKeyPair.generate();
  
//   print('2. Bob generates a signed prekey...');
//   final bobSignedPreKey = await SignedPreKey.generate(1, bobIdentityKeyPair);
  
//   print('3. Bob generates one-time prekeys...');
//   final bobOneTimePreKeys = await OneTimePreKey.generateBatch(5);
  
//   // Bob publishes his prekey bundle to the server
//   print('4. Bob creates and publishes his prekey bundle...');
//   final bobBundle = PreKeyBundle(
//     x2IdPubKey: bobIdentityKeyPair.x2PubKey,
//     edIdPubKey: bobIdentityKeyPair.edPubKey,
//     signedPreKey: bobSignedPreKey,
//     oneTimePreKey: bobOneTimePreKeys.first, // Use first one-time key
//   );
  
//   // Serialize for transmission
//   final bobBundleJson = bobBundle.serializePublic();
//   print('   Bundle size: ${bobBundleJson.length} bytes');
//   print('   Bundle (truncated): ${bobBundleJson.substring(0, 100)}...\n');

//   // --- Alice's Setup (Client-side) ---
//   print('5. Alice generates her identity keys...');
//   final aliceIdentityKeyPair = await IdentityKeyPair.generate();
  
//   // Alice receives Bob's bundle from server and deserializes it
//   print('6. Alice retrieves Bob\'s prekey bundle from server...');
//   final receivedBobBundle = PreKeyBundle.deserializePublic(bobBundleJson);
  
//   // Alice initiates the X3DH handshake
//   print('7. Alice performs X3DH handshake...');
//   final aliceResult = await X3DH.initiateHandshake(
//     aliceIdentityKeyPair: aliceIdentityKeyPair,
//     bobPreKeyBundle: receivedBobBundle,
//     info: "MyMessagingApp",
//   );
  
//   print('   ✓ Alice derived shared secret');
//   print('   Shared secret: ${base64Encode(aliceResult.sharedSecret).substring(0, 20)}...');
//   print('   Ephemeral key: ${base64Encode(aliceResult.ephemeralKey).substring(0, 20)}...\n');

//   // --- Bob Completes Handshake ---
//   print('8. Bob receives Alice\'s ephemeral key and completes handshake...');
//   final bobResult = await X3DH.completeHandshake(
//     bobIdentityKeyPair: bobIdentityKeyPair,
//     bobSignedPreKey: bobSignedPreKey,
//     bobOneTimePreKey: bobOneTimePreKeys.first,
//     aliceIdentityPubKey: aliceIdentityKeyPair.x2PubKey,
//     aliceEphemeralPubKey: aliceResult.ephemeralKey,
//     info: "MyMessagingApp",
//   );
  
//   print('   ✓ Bob derived shared secret');
//   print('   Shared secret: ${base64Encode(bobResult.sharedSecret).substring(0, 20)}...\n');

//   // --- Verification ---
//   print('9. Verifying both parties have the same shared secret...');
//   final secretsMatch = base64Encode(aliceResult.sharedSecret) == 
//                        base64Encode(bobResult.sharedSecret);
  
//   if (secretsMatch) {
//     print('   ✓ SUCCESS! Both parties derived identical shared secrets!');
//     print('   The shared secret can now be used for encrypted communication.\n');
//   } else {
//     print('   ✗ FAILED! Shared secrets do not match!');
//   }

//   print('=== X3DH Example Complete ===');
}