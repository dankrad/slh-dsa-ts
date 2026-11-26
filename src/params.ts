/** FIPS 205 Table 2: the twelve pure SLH-DSA parameter sets. */
export const PARAMETER_NAMES = Object.freeze([
  'SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHA2-192s', 'SLH-DSA-SHA2-192f',
  'SLH-DSA-SHA2-256s', 'SLH-DSA-SHA2-256f',
  'SLH-DSA-SHAKE-128s', 'SLH-DSA-SHAKE-128f',
  'SLH-DSA-SHAKE-192s', 'SLH-DSA-SHAKE-192f',
  'SLH-DSA-SHAKE-256s', 'SLH-DSA-SHAKE-256f',
] as const);

export type ParameterName = typeof PARAMETER_NAMES[number];
export interface Parameters {
  readonly name: ParameterName;
  readonly family: 'SHA2' | 'SHAKE';
  readonly n: number;
  readonly h: number;
  readonly d: number;
  readonly hp: number;
  readonly a: number;
  readonly k: number;
  readonly m: number;
  readonly len: number;
  readonly mdBytes: number;
  readonly treeBytes: number;
  readonly leafBytes: number;
  readonly xmssSignatureBytes: number;
  readonly forsSignatureBytes: number;
  readonly signatureBytes: number;
  readonly publicKeyBytes: number;
  readonly secretKeyBytes: number;
}

const rows = [
  [16, 63, 7, 9, 12, 14, 30], [16, 66, 22, 3, 6, 33, 34],
  [24, 63, 7, 9, 14, 17, 39], [24, 66, 22, 3, 8, 33, 42],
  [32, 64, 8, 8, 14, 22, 47], [32, 68, 17, 4, 9, 35, 49],
] as const;

export const PARAMETERS: Readonly<Record<ParameterName, Parameters>> = Object.freeze(
  Object.fromEntries(PARAMETER_NAMES.map((name, i) => {
    const [n, h, d, hp, a, k, m] = rows[i % 6]!;
    const len = 2 * n + 3;
    const xmssSignatureBytes = (len + hp) * n;
    const forsSignatureBytes = k * (a + 1) * n;
    return [name, Object.freeze({
      name, family: i < 6 ? 'SHA2' : 'SHAKE', n, h, d, hp, a, k, m, len,
      mdBytes: Math.ceil(k * a / 8), treeBytes: Math.ceil((h - hp) / 8),
      leafBytes: Math.ceil(hp / 8), xmssSignatureBytes, forsSignatureBytes,
      signatureBytes: n + forsSignatureBytes + d * xmssSignatureBytes,
      publicKeyBytes: 2 * n, secretKeyBytes: 4 * n,
    })];
  })) as Record<ParameterName, Parameters>,
);

/** Unsupported names are programmer errors, including at verification. */
export function getParameters(name: ParameterName): Parameters {
  if (typeof name !== 'string' || !Object.hasOwn(PARAMETERS, name)) {
    throw new RangeError(`Unsupported SLH-DSA parameter set: ${String(name)}`);
  }
  return PARAMETERS[name];
}
