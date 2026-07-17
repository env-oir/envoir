// safety.js — the identity SAFETY NUMBER (spec §3.4 key verification, §3.9.1 encoding).
//
// The KEY is the identity and the trust anchor. A *name@domain* address is only a pointer to
// it (spec §3.9). To detect a look-alike/spoofed key, two people compare a **safety number**
// out-of-band (read the words aloud, scan the QR-grid, or compare digits) — exactly like
// Signal's safety numbers. Same key in → same safety number out, deterministically; two
// different keys yield different safety numbers by construction, so a mismatch is a red flag.
//
// This is the SAME derivation the old client used as an "8-word key-name", now correctly
// framed: it is a *verification affordance*, NOT an address. Addresses are name@domain.
//
// What is real here: the SHA-256 digest (Web Crypto) and the word/number arithmetic are real
// and fully deterministic. What is a stand-in: the spec (§2.2, §3.9.1) specifies BLAKE3 and a
// curated ~1024-word list at 10 bits/word for a full 2^80 space; browsers have no BLAKE3, so
// this uses SHA-256 and a byte-aligned 256-word list (8 bits/word). A production client ships
// the full list and derives the number over BOTH parties' keys (this demo has only yours).

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

if (WORDLIST.length !== 256) throw new Error('safety wordlist must have exactly 256 entries, has ' + WORDLIST.length);

export { WORDLIST as SAFETY_WORDS };

async function digestOf(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// Derive a deterministic safety number from raw public-key bytes. Returns:
//  - words[8] + checksum   (spoken / read-aloud form)
//  - numeric               (Signal-style 12×5-digit blocks, for out-of-band comparison)
//  - grid[8][8]            (a QR-like fingerprint the eye can compare at a glance)
// Pure function of the input bytes.
export async function deriveSafety(rawPublicKeyBytes) {
  const digest = await digestOf(rawPublicKeyBytes);
  const words = [];
  for (let i = 0; i < 8; i++) words.push(WORDLIST[digest[i]]);
  let fold = 0;
  for (let i = 8; i < digest.length; i++) fold ^= digest[i];
  for (let i = 0; i < 8; i++) fold = (fold + digest[i] * (i + 1)) % 256;
  const checksum = WORDLIST[fold];

  // Numeric form: 12 blocks of 5 digits, folded from the full digest.
  let numeric = '';
  for (let i = 0; i < 12; i++) {
    const a = digest[(i * 2) % 32], b = digest[(i * 2 + 1) % 32], c = digest[(i * 3 + 7) % 32];
    const n = ((a << 8) ^ (b << 3) ^ c) % 100000;
    numeric += String(n).padStart(5, '0') + (i < 11 ? ' ' : '');
  }

  // Grid form: 8×8 cells, filled from the bits of a re-hash (so it differs visibly from words).
  const g2 = await digestOf(digest);
  const grid = [];
  for (let r = 0; r < 8; r++) {
    const row = [];
    for (let c = 0; c < 8; c++) {
      const bit = (g2[(r * 8 + c) % 32] >> (c % 8)) & 1;
      row.push(bit);
    }
    grid.push(row);
  }

  return { words, checksum, full: words.concat(checksum).join('-'), numeric, grid };
}

// Re-derive and compare — demonstrates determinism (same key → identical result, every time).
export async function verifySafety(rawPublicKeyBytes, expectedFull) {
  const again = await deriveSafety(rawPublicKeyBytes);
  return { match: again.full === expectedFull, recomputed: again.full };
}

// Key-name (spec §3.9.6): the zero-authority FLOOR of the naming ladder (§3.13.2) — an 8-word,
// no-"@" name derived SOLELY from the identity's own public key. No lookup, no DNS, no
// name-chain, no registration: whoever holds the key already holds this name, and no authority
// can allocate, deny, seize, or repoint it (resolver-type `self`, §3.12.4 — "resolution" is a
// local derivation, nothing to KT-audit because the binding *is* the key).
//
// Domain-separated from the safety number above by a single trailing tag byte before hashing,
// so the two word-sequences differ even though both are ultimately digests of key material —
// exactly the spec §3.9.6 "not a safety number" distinction: the key-name may be typed at to
// reach someone (an address, floor rung of §3.13.2); the safety number never routes and only
// confirms an out-of-band pin (§3.4.1). Rendered dot-joined (no "@") to read as one addressable
// token rather than a sentence.
export async function deriveKeyName(rawPublicKeyBytes) {
  const tagged = new Uint8Array(rawPublicKeyBytes.length + 1);
  tagged.set(rawPublicKeyBytes, 0);
  tagged[rawPublicKeyBytes.length] = 0x4b; // ASCII 'K' — keyname domain-separator tag
  const digest = await digestOf(tagged);
  const words = [];
  for (let i = 0; i < 8; i++) words.push(WORDLIST[digest[i]]);
  return words.join('.');
}

// A lightweight safety number derived from an opaque contact key string (demo contacts don't
// carry real key bytes). Deterministic per string so a contact's number is stable in the UI.
export async function deriveSafetyFromString(s) {
  return deriveSafety(new TextEncoder().encode('contact:' + (s || '')));
}
