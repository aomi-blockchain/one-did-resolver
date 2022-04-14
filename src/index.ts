import multibase from 'multibase';
import varint from 'varint';
import * as secp256k1 from './secp256k1';
import * as ed25519 from './ed25519';
import { DIDResolutionOptions, ParsedDID, Resolvable } from 'did-resolver';
import { KeyToDidDocFunc } from './KeyToDidDoc';

const DID_LD_JSON = 'application/did+ld+json';
const DID_JSON = 'application/did+json';


const prefixToDriverMap: Record<any, KeyToDidDocFunc> = {
  0xe7: secp256k1.keyToDidDoc,
  0xed: ed25519.keyToDidDoc
};

export function getResolver() {
  return {
    one: async (did: string, parsed: ParsedDID, resolver: Resolvable, options: DIDResolutionOptions) => {
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
        const doc: any = await prefixToDriverMap[keyType](pubKeyBytes, parsed.id);
        if (contentType === DID_LD_JSON) {
          doc['@context'] = 'https://w3id.org/did/v1';
          response.didDocument = doc;
        } else if (contentType === DID_JSON) {
          response.didDocument = doc;
        } else {
          delete response.didResolutionMetadata.contentType;
          response.didResolutionMetadata.error = 'representationNotSupported';
        }
      } catch (e: any) {
        response.didResolutionMetadata.error = 'invalidDid';
        response.didResolutionMetadata.message = e.toString();
      }
      return response;
    }
  };
}
