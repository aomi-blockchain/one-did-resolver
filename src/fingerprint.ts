import { decodeBase64 } from 'dids/lib/utils';

export function fingerprintParse(fingerprint: string) {
  const [flagb64, id] = fingerprint.split('.');
  const flagBytes = decodeBase64(flagb64);
  const flag = String.fromCharCode.apply(null, flagBytes as any);
  return [flag, id];
}
