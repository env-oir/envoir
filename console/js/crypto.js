// crypto.js — REAL Web Crypto for the management console. Keygen + signing + hashing +
// deterministic safety-number derivation, ported to stand alone from the reference client
// (client/js/identity.js + client/js/safety.js). Everything here is real browser crypto:
//
//   • The domain authority holds a real Ed25519 keypair (ECDSA-P256 fallback, labeled) and
//     really SIGNS the DomainDirectory object it publishes (spec §18.4.7, §3.10.3).
//   • A SOVEREIGN member's key is generated on "their device" and the private key is discarded
//     immediately — the org keeps only the public key + name binding. It literally cannot sign
//     or decrypt as them (spec §3.10.2a).
//   • An ORG-MANAGED member's private key is generated AND retained in a disclosed escrow, so
//     the console can demonstrably sign as them — the honest cost of that model (spec §3.10.2b).
//
// Stand-in, honestly labeled: SHA-256 substitutes for the spec's BLAKE3 content-addressing and
// safety-number hash; a byte-aligned 256-word list (8 bits/word) stands in for the ~1024-word
// list; threshold (FROST) signing is simulated — a single Ed25519 signature stands in for the
// quorum signature once the console has collected a threshold of approvals (spec §5.8.6).

// ---- primitives ---------------------------------------------------------------------------
export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
export function toB64u(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64u(s) {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
export function hex(bytes, max) {
  const s = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return max ? s.slice(0, max) : s;
}

async function genSigningKey() {
  try {
    return { kp: await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']), alg: 'Ed25519' };
  } catch {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { kp, alg: 'ECDSA-P256 (Ed25519 unsupported here)' };
  }
}

async function exportRawPub(publicKey) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)
    .catch(async () => new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))));
}

// Generate a fresh identity keypair. Returns { alg, ik(pub b64u), fingerprint, safety, priv }.
// `priv` is a serialised PKCS#8 (b64u) — the caller decides whether to KEEP it (org-managed
// escrow) or DISCARD it (sovereign). Sovereign discarding is what makes the guarantee real.
export async function generateKeypair() {
  const { kp, alg } = await genSigningKey();
  const raw = await exportRawPub(kp.publicKey);
  const pk8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  return {
    alg,
    ik: toB64u(raw),
    fingerprint: hex(await sha256(raw), 16),
    safety: await deriveSafety(raw),
    priv: toB64u(pk8),
  };
}

// Import a retained private key (org-managed escrow) and sign bytes with it — this is the
// console actually exercising the escrowed key, proving the "org CAN impersonate" cost.
export async function signWithPriv(privB64u, alg, bytes) {
  const algo = (alg || '').startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  const key = await crypto.subtle.importKey('pkcs8', fromB64u(privB64u), algo, false, ['sign']);
  const signAlg = (alg || '').startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' };
  return new Uint8Array(await crypto.subtle.sign(signAlg, key, bytes));
}

// ---- safety number (spec §3.4) ------------------------------------------------------------
const WORDLIST = (
  'otter heron wolf lynx puma ibex crane finch ' +
  'swan hawk owl fox stag elk seal orca ' +
  'whale dolphin panda koala lemur raven badger beaver ' +
  'marten weasel ferret gecko iguana viper cobra egret ' +
  'falcon eagle sparrow robin wren plover osprey kestrel ' +
  'harrier bison moose caribou antelope gazelle jackal hyena ' +
  'walrus narwhal pelican heronry stork toucan parrot macaw ' +
  'canary linnet siskin bunting warbler thrush maple cedar ' +
  'birch willow aspen elm oak pine fir spruce ' +
  'alder rowan hazel poplar yew larch fern moss ' +
  'lichen clover thistle nettle bramble ivy vine reed ' +
  'rush sedge bamboo cactus aloe agave lotus lily ' +
  'iris tulip daisy poppy violet aster crocus jasmine ' +
  'orchid lavender sage basil mint thyme garnet opal ' +
  'topaz jasper onyx agate quartz cobalt amber jade ' +
  'coral pearl ruby beryl zircon spinel granite basalt ' +
  'slate marble shale flint pumice obsidian mica pyrite ' +
  'gypsum talc feldspar dolomite chert schist copper bronze ' +
  'brass iron steel tin zinc nickel silver gold ' +
  'platinum titanium tungsten cadmium chrome crimson ochre indigo ' +
  'cyan teal emerald olive umber sienna russet ivory ' +
  'pewter charcoal ash chalk cream beige tan khaki ' +
  'mauve lilac plum peach salmon dawn dusk noon ' +
  'twilight midnight sunrise sunset zenith solstice equinox aurora ' +
  'eclipse comet meteor nebula nova cloud storm thunder ' +
  'lightning breeze gale zephyr mist fog frost dew ' +
  'rain hail sleet snow gust delta ridge canyon ' +
  'valley plateau mesa summit peak glacier tundra prairie ' +
  'savanna steppe fjord isthmus atoll harbor cove bay ' +
  'strait channel estuary reef lagoon marsh bog fen ' +
  'moor heath dune shoal cape ember flame spark ' +
  'cinder kindle hearth forge anvil bellows chisel mallet'
).split(' ');

export async function deriveSafety(rawPublicKeyBytes) {
  const digest = await sha256(rawPublicKeyBytes);
  const words = [];
  for (let i = 0; i < 8; i++) words.push(WORDLIST[digest[i]]);
  let fold = 0;
  for (let i = 8; i < digest.length; i++) fold ^= digest[i];
  for (let i = 0; i < 8; i++) fold = (fold + digest[i] * (i + 1)) % 256;
  const checksum = WORDLIST[fold];
  let numeric = '';
  for (let i = 0; i < 12; i++) {
    const a = digest[(i * 2) % 32], b = digest[(i * 2 + 1) % 32], c = digest[(i * 3 + 7) % 32];
    const n = ((a << 8) ^ (b << 3) ^ c) % 100000;
    numeric += String(n).padStart(5, '0') + (i < 11 ? ' ' : '');
  }
  const g2 = await sha256(digest);
  const grid = [];
  for (let r = 0; r < 8; r++) {
    const row = [];
    for (let c = 0; c < 8; c++) row.push((g2[(r * 8 + c) % 32] >> (c % 8)) & 1);
    grid.push(row);
  }
  return { words, checksum, full: words.concat(checksum).join('-'), numeric, grid };
}

// A stable safety number for a seeded member that carries no real key bytes (demo data).
export async function deriveSafetyFromString(s) {
  return deriveSafety(new TextEncoder().encode('member:' + (s || '')));
}
