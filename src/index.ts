import multibase from 'multibase';
import varint from 'varint';
import * as secp256k1 from './secp256k1';
import * as ed25519  from './ed25519';

const DID_LD_JSON = 'application/did+ld+json';
const DID_JSON = 'application/did+json';

const prefixToDriverMap = {
  0xe7: secp256k1,
  0xed: ed25519
};

export function getResolver() {
  return {
    one: async (did, parsed, r, options) => {
      const contentType = options.accept || DID_JSON;
      const response: any = {
        didResolutionMetadata: { contentType },
        didDocument: null,
        didDocumentMetadata: {}
      };
      try {
        const [_, id] = parsed.id.split('.');

        const multicodecPubKey = multibase.decode(id);
        const keyType = varint.decode(multicodecPubKey);
        const pubKeyBytes = multicodecPubKey.slice(varint.decode.bytes);
        const doc: any = await prefixToDriverMap[keyType].keyToDidDoc(pubKeyBytes, parsed.id);
        if (contentType === DID_LD_JSON) {
          doc['@context'] = 'https://w3id.org/did/v1';
          response.didDocument = doc;
        } else if (contentType === DID_JSON) {
          response.didDocument = doc;
        } else {
          delete response.didResolutionMetadata.contentType;
          response.didResolutionMetadata.error = 'representationNotSupported';
        }
      } catch (e) {
        response.didResolutionMetadata.error = 'invalidDid';
        response.didResolutionMetadata.message = e.toString();
      }
      return response;
    }
  };
}
