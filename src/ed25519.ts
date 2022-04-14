import u8a from 'uint8arrays';
import { decodeBase64 } from 'dids/lib/utils';
import { fingerprintParse } from './fingerprint';

export function keyToDidDoc(pubKeyBytes, fingerprint) {

  const [flag] = fingerprintParse(fingerprint);

  const did = `did:one:${fingerprint}`;
  const keyId = `${did}#${fingerprint}`;
  return {
    id: did,
    flag,
    verificationMethod: [
      {
        id: keyId,
        type: 'Secp256k1VerificationKey2018',
        controller: did,
        publicKeyBase58: u8a.toString(pubKeyBytes, 'base58btc')
      }
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    capabilityInvocation: [keyId]
  };
}
