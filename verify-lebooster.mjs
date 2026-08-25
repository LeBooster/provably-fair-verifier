#!/usr/bin/env node
/**
 * Vérificateur indépendant des tirages LeBooster — algo_version = "pf-v1".
 *
 * Un seul fichier, aucune dépendance : uniquement `node:crypto`, qui fournit
 * SHA-256 et HMAC-SHA-256. Tu peux le lire en entier avant de l'exécuter, c'est
 * le but. Le programme ne contacte aucun serveur et n'écrit rien : il lit un
 * fichier de preuve, refait le calcul, et affiche chaque étape.
 *
 * Usage :
 *   node verify-lebooster.mjs preuve.json
 *   node verify-lebooster.mjs preuve.json --json     (sortie machine)
 *   node verify-lebooster.mjs --self-test            (vecteurs de référence)
 *
 * Code de sortie : 0 si la preuve est valide, 1 sinon.
 *
 * Ce fichier est la transcription littérale de l'algorithme de production
 * (`packages/shared/src/provably-fair` dans le dépôt LeBooster). Un test du
 * dépôt rejoue les vecteurs de `kat.json` à travers CE fichier et compare au
 * moteur de production : les deux ne peuvent pas diverger sans casser la CI.
 */

import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// 1. Primitives cryptographiques (PF §2.2, §2.3)
// ---------------------------------------------------------------------------

/** 2^32, borne du tirage d'un entier 32 bits. */
const MAX_U32 = 4294967296;

const hexToBytes = (hex) => Buffer.from(hex, 'hex');
const bytesToHex = (bytes) => Buffer.from(bytes).toString('hex');

/** commit = hex(SHA-256(server_seed)) — l'engagement publié AVANT l'ouverture. */
const computeCommit = (serverSeedHex) =>
  createHash('sha256').update(hexToBytes(serverSeedHex)).digest('hex');

/**
 * draw = HMAC-SHA-256(clé = server_seed, message = "client_seed:nonce").
 *
 * La clé est la graine serveur DÉCODÉE depuis l'hexadécimal (octets bruts). La
 * graine client est une chaîne opaque utilisée telle quelle, jamais ré-encodée.
 * Le nonce est sérialisé en décimal, séparé par « : ».
 */
const computeDraw = (serverSeedHex, clientSeed, nonce) =>
  createHmac('sha256', hexToBytes(serverSeedHex)).update(`${clientSeed}:${nonce}`, 'utf8').digest();

/**
 * Ré-expansion déterministe du tirage en flux indépendants :
 * stream(draw, label, i) = HMAC-SHA-256(clé = draw, message = "label:i").
 * Le digest du tirage sert de clé ; `label` et `i` séparent les usages.
 */
const streamBytes = (draw, label, i) =>
  createHmac('sha256', draw).update(`${label}:${i}`, 'utf8').digest();

/** Entier 32 bits non signé, gros-boutiste, lu à l'offset donné. */
const u32BE = (bytes, offset = 0) =>
  ((bytes[offset] << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3]) >>>
  0;

/** Les 32 premiers bits ramenés dans [0, 1). */
const float01 = (bytes, offset = 0) => u32BE(bytes, offset) / MAX_U32;

/** hex(SHA-256(sérialisation canonique du pool figé)) — clés de rareté triées. */
const poolDigest = (pools) => {
  const canonical = {};
  for (const rarity of Object.keys(pools).sort()) canonical[rarity] = pools[rarity];
  return createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex');
};

// ---------------------------------------------------------------------------
// 2. Barème des raretés (PF-BARÈME)
// ---------------------------------------------------------------------------

/** NFD → suppression des diacritiques → minuscules → espaces compactés. */
const normalizeRarity = (rarity) =>
  rarity
    .normalize('NFD')
    .replace(new RegExp('[\\u0300-\\u036f]', 'g'), '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();

/** alias normalisé → rang. Une rareté inconnue vaut 0. */
const buildRankLookup = (bareme) => {
  const lookup = new Map();
  for (const entry of bareme) {
    for (const alias of entry.aliases) lookup.set(normalizeRarity(alias), entry.rank);
  }
  return lookup;
};

const rankOf = (rarity, lookup) => lookup.get(normalizeRarity(rarity)) ?? 0;

// ---------------------------------------------------------------------------
// 3. Anti-malchance (PF-06)
// ---------------------------------------------------------------------------

/**
 * Évaluée une seule fois par ouverture, sur le slot d'index le plus élevé.
 * Ne dégrade jamais une rareté : elle remet le compteur à zéro quand le tirage
 * naturel atteint déjà la garantie, ou force la bande garantie au seuil.
 */
const applyPity = (drawnRarity, pity, isPitySlot, lookup) => {
  if (!isPitySlot) return { rarity: drawnRarity, counterAfter: pity.counter, triggered: false };

  const drawnRank = rankOf(drawnRarity, lookup);
  const guaranteedRank = rankOf(pity.guaranteedRarity, lookup);

  if (drawnRank >= guaranteedRank)
    return { rarity: drawnRarity, counterAfter: 0, triggered: false };
  if (pity.counter + 1 >= pity.threshold)
    return { rarity: pity.guaranteedRarity, counterAfter: 0, triggered: true };
  return { rarity: drawnRarity, counterAfter: pity.counter + 1, triggered: false };
};

// ---------------------------------------------------------------------------
// 4. Rejeu complet, étape par étape (PF §6.4)
// ---------------------------------------------------------------------------

/** Au-delà, on considère l'échantillonnage cassé plutôt que de boucler sans fin. */
const MAX_REJECTION_ATTEMPTS = 32;

function explain(proof, snapshots, claimedCards) {
  const steps = { commit: null, draw: null, pool: null, slots: [], mappingOk: null };

  const computedCommit = computeCommit(proof.serverSeed);
  steps.commit = {
    formula: 'commit = hex(SHA-256(server_seed))',
    computed: computedCommit,
    expected: proof.commit,
    ok: computedCommit === proof.commit,
  };

  const drawBytes = computeDraw(proof.serverSeed, proof.clientSeed, proof.nonce);
  const drawHex = bytesToHex(drawBytes);
  steps.draw = {
    formula: 'draw = hex(HMAC-SHA-256(clé = server_seed, message = "client_seed:nonce"))',
    message: `${proof.clientSeed}:${proof.nonce}`,
    computed: drawHex,
    expected: proof.draw ?? null,
    ok: proof.draw === undefined || proof.draw === null ? true : drawHex === proof.draw,
  };

  const { packRules, pity } = snapshots;

  if (proof.poolDigest) {
    const computed = poolDigest(packRules.pools);
    steps.pool = {
      formula: 'pool_digest = hex(SHA-256(pool ordonné, clés de rareté triées))',
      computed,
      expected: proof.poolDigest,
      ok: computed === proof.poolDigest,
    };
  }

  const lookup = buildRankLookup(packRules.rankBareme);
  const remaining = {};
  for (const rarity of Object.keys(packRules.pools))
    remaining[rarity] = [...packRules.pools[rarity]];

  // L'ordre d'ÉVALUATION est slot.index croissant, distinct de l'ordre d'affichage.
  const slots = [...packRules.slots].sort((a, b) => a.index - b.index);
  if (new Set(slots.map((s) => s.index)).size !== slots.length) {
    throw new Error('les slot.index doivent être uniques (PF-07)');
  }
  const highestIndex = slots.length > 0 ? slots[slots.length - 1].index : null;
  const claimedBySlot = new Map((claimedCards ?? []).map((c) => [c.slot, c]));
  let mappingMatches = (claimedCards ?? []).length === slots.length;

  slots.forEach((slot, evalPos) => {
    // 4.1 — Sous-flux de rareté : stream(draw, "rarity", evalPos).
    const rarityBytes = streamBytes(drawBytes, 'rarity', evalPos);
    const u32r = u32BE(rarityBytes, 0);
    const r = float01(rarityBytes, 0);

    // 4.2 — Fonction de répartition sur les odds, dans l'ordre du snapshot.
    const totalWeight = slot.odds.reduce((s, o) => s + o.weight, 0);
    let running = 0;
    let drawnRarity = slot.odds[slot.odds.length - 1]?.rarity ?? '';
    let picked = false;
    const cdf = slot.odds.map((o) => {
      running += totalWeight > 0 ? o.weight / totalWeight : 0;
      const selected = !picked && r < running;
      if (selected) {
        drawnRarity = o.rarity;
        picked = true;
      }
      return { rarity: o.rarity, weight: o.weight, cumulative: running, selected };
    });

    // 4.3 — Anti-malchance, uniquement sur le slot d'index le plus élevé.
    const isPitySlot = slot.index === highestIndex;
    const outcome = applyPity(drawnRarity, pity, isPitySlot, lookup);
    const finalRarity = outcome.rarity;

    // 4.4 — Choix de la carte par échantillonnage avec rejet, sans remise.
    const poolBefore = [...(remaining[finalRarity] ?? [])];
    const n = poolBefore.length;
    if (n === 0)
      throw new Error(`pool épuisé pour la rareté « ${finalRarity} » (evalPos ${evalPos})`);
    const rejectionLimit = Math.floor(MAX_U32 / n) * n;
    const attempts = [];
    let chosenIndex = -1;
    for (let i = 0; i < MAX_REJECTION_ATTEMPTS; i++) {
      const v = u32BE(streamBytes(drawBytes, `card:${evalPos}`, i), 0);
      const accepted = v < rejectionLimit;
      attempts.push({ i, u32: v, accepted });
      if (accepted) {
        chosenIndex = v % n;
        break;
      }
    }
    if (chosenIndex < 0) throw new Error(`échantillonnage sans issue au slot ${slot.index}`);
    const cardId = poolBefore[chosenIndex];
    remaining[finalRarity].splice(chosenIndex, 1);

    const claimed = claimedBySlot.get(slot.index) ?? null;
    const ok = claimed !== null && claimed.rarity === finalRarity && claimed.cardId === cardId;
    if (!ok) mappingMatches = false;

    steps.slots.push({
      slotIndex: slot.index,
      evalPos,
      rarity: {
        substream: `rarity:${evalPos}`,
        substreamHex: bytesToHex(rarityBytes),
        u32: u32r,
        r,
        totalWeight,
        cdf,
        drawnRarity,
      },
      pity: {
        isPitySlot,
        triggered: outcome.triggered,
        finalRarity,
        counterAfter: outcome.counterAfter,
      },
      card: { rarity: finalRarity, poolBefore, n, rejectionLimit, attempts, chosenIndex, cardId },
      claimedRarity: claimed?.rarity ?? null,
      claimedCardId: claimed?.cardId ?? null,
      ok,
    });
  });

  steps.mappingOk = (claimedCards ?? []).length === 0 ? null : mappingMatches;
  steps.allOk =
    steps.commit.ok && steps.draw.ok && (steps.pool?.ok ?? true) && steps.mappingOk !== false;
  return steps;
}

// ---------------------------------------------------------------------------
// 5. Affichage
// ---------------------------------------------------------------------------

const mark = (ok) => (ok ? '✓' : '✗');

function render(steps, proof) {
  const out = [];
  const p = (s = '') => out.push(s);
  // Numérotation dynamique : l'empreinte du pool n'est vérifiée que si la preuve la porte.
  let stepNo = 0;
  const title = (label) => `ÉTAPE ${++stepNo} — ${label}`;

  p('══════════════════════════════════════════════════════════════════');
  p("  VÉRIFICATION D'UN TIRAGE LEBOOSTER — algo pf-v1");
  p('══════════════════════════════════════════════════════════════════');
  p();
  p(title("L'engagement pris avant l'ouverture"));
  p(`  ${steps.commit.formula}`);
  p(`  graine serveur : ${proof.serverSeed}`);
  p(`  recalculé      : ${steps.commit.computed}`);
  p(`  publié         : ${steps.commit.expected}`);
  p(
    `  ${mark(steps.commit.ok)} ${steps.commit.ok ? "identiques : la graine n'a pas été changée après coup." : "DIFFÉRENTS : la graine révélée n'est pas celle engagée."}`
  );
  p();
  p(title('Le tirage'));
  p(`  ${steps.draw.formula}`);
  p(`  message   : "${steps.draw.message}"`);
  p(`  recalculé : ${steps.draw.computed}`);
  if (steps.draw.expected) p(`  publié    : ${steps.draw.expected}`);
  p(
    `  ${mark(steps.draw.ok)} ${steps.draw.ok ? 'le tirage dérive bien des deux graines et du nonce.' : 'DIFFÉRENT du tirage publié.'}`
  );

  if (steps.pool) {
    p();
    p(title('Le pool figé'));
    p(`  ${steps.pool.formula}`);
    p(`  recalculé : ${steps.pool.computed}`);
    p(`  publié    : ${steps.pool.expected}`);
    p(
      `  ${mark(steps.pool.ok)} ${steps.pool.ok ? 'le pool fourni est bien celui figé au tirage.' : "le pool ne correspond pas à l'empreinte publiée."}`
    );
  }

  p();
  p(title('Du tirage aux cartes, slot par slot'));
  p("  (ordre d'évaluation : slot.index croissant, sans remise)");

  for (const s of steps.slots) {
    p();
    p(
      `  ┌─ slot ${s.slotIndex} (position d'évaluation ${s.evalPos}) ${'─'.repeat(Math.max(0, 40 - String(s.slotIndex).length))}`
    );
    p(`  │ a. sous-flux « ${s.rarity.substream} » = HMAC-SHA-256(draw, "${s.rarity.substream}")`);
    p(`  │    ${s.rarity.substreamHex}`);
    p(`  │    4 premiers octets → u32 = ${s.rarity.u32}`);
    p(`  │    r = ${s.rarity.u32} / 2^32 = ${s.rarity.r.toFixed(10)}`);
    p('  │');
    p(`  │ b. bande de rareté (poids total ${s.rarity.totalWeight})`);
    for (const row of s.rarity.cdf) {
      p(
        `  │    ${row.selected ? '→' : ' '} ${row.rarity.padEnd(26)} poids ${String(row.weight).padStart(6)}  cumul < ${row.cumulative.toFixed(10)}${row.selected ? '  ← r tombe ici' : ''}`
      );
    }
    p(`  │    bande tirée : ${s.rarity.drawnRarity}`);
    p('  │');
    p(`  │ c. anti-malchance : ${s.pity.isPitySlot ? 'slot évalué' : 'non évalué sur ce slot'}`);
    if (s.pity.isPitySlot) {
      p(
        `  │    ${s.pity.triggered ? 'seuil atteint → bande garantie forcée' : 'pas de forçage, tirage naturel conservé'}`
      );
      p(`  │    compteur après cette ouverture : ${s.pity.counterAfter}`);
    }
    p(`  │    rareté retenue : ${s.pity.finalRarity}`);
    p('  │');
    p(
      `  │ d. carte tirée dans le pool restant de « ${s.card.rarity} » (${s.card.n} carte${s.card.n > 1 ? 's' : ''})`
    );
    p(
      `  │    borne anti-biais = floor(2^32 / ${s.card.n}) × ${s.card.n} = ${s.card.rejectionLimit}`
    );
    for (const a of s.card.attempts) {
      p(
        `  │    essai ${a.i} : HMAC(draw, "card:${s.evalPos}:${a.i}") → u32 = ${String(a.u32).padStart(10)} ${a.accepted ? '< borne → accepté' : '≥ borne → rejeté, on rejoue'}`
      );
    }
    p(
      `  │    index = ${s.card.attempts[s.card.attempts.length - 1].u32} mod ${s.card.n} = ${s.card.chosenIndex}`
    );
    p(`  │    pool avant : [${s.card.poolBefore.join(', ')}]`);
    p(`  │    carte      : ${s.card.cardId}`);
    if (s.claimedCardId !== null) {
      p('  │');
      p(`  │ ${mark(s.ok)} annoncé par LeBooster : ${s.claimedRarity} / ${s.claimedCardId}`);
    }
    p(`  └${'─'.repeat(58)}`);
  }

  p();
  p('══════════════════════════════════════════════════════════════════');
  p(`  ${mark(steps.commit.ok)} engagement    ${steps.commit.ok ? 'conforme' : 'NON CONFORME'}`);
  p(`  ${mark(steps.draw.ok)} tirage        ${steps.draw.ok ? 'conforme' : 'NON CONFORME'}`);
  if (steps.pool)
    p(`  ${mark(steps.pool.ok)} pool figé     ${steps.pool.ok ? 'conforme' : 'NON CONFORME'}`);
  if (steps.mappingOk !== null)
    p(
      `  ${mark(steps.mappingOk)} cartes        ${steps.mappingOk ? 'identiques à celles annoncées' : 'DIFFÉRENTES de celles annoncées'}`
    );
  p();
  p(`  ${steps.allOk ? '✓ TIRAGE VÉRIFIÉ' : '✗ VÉRIFICATION EN ÉCHEC'}`);
  p('══════════════════════════════════════════════════════════════════');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// 6. Auto-test sur les vecteurs de référence
// ---------------------------------------------------------------------------

function selfTest() {
  const here = dirname(fileURLToPath(import.meta.url));
  const vectors = JSON.parse(readFileSync(join(here, 'kat.json'), 'utf8'));
  let failures = 0;

  for (const v of vectors) {
    const proof = {
      commit: v.expected.commit,
      serverSeed: v.input.serverSeedHex,
      clientSeed: v.input.clientSeed,
      nonce: v.input.nonce,
      draw: v.expected.draw,
    };
    const snapshots = { packRules: v.input.packRules, pity: v.input.pity };
    let ok = false;
    let detail = '';
    try {
      const steps = explain(proof, snapshots, v.expected.cards);
      ok = steps.allOk;
      if (!ok) detail = `commit=${steps.commit.ok} draw=${steps.draw.ok} cartes=${steps.mappingOk}`;
    } catch (e) {
      detail = e.message;
    }
    if (!ok) failures++;
    console.log(`  ${mark(ok)} ${v.name.padEnd(22)} ${detail}`);
  }

  console.log();
  if (failures === 0) {
    console.log(`✓ ${vectors.length} vecteurs de référence reproduits à l'identique.`);
    return 0;
  }
  console.log(`✗ ${failures} vecteur(s) en échec.`);
  return 1;
}

// ---------------------------------------------------------------------------
// 7. Entrée
// ---------------------------------------------------------------------------

const USAGE = `Vérificateur de tirage LeBooster (pf-v1)

  node verify-lebooster.mjs <preuve.json>     vérifie une preuve, détail complet
  node verify-lebooster.mjs <preuve.json> --json   même chose, en JSON
  node verify-lebooster.mjs --self-test       rejoue les vecteurs de référence

La preuve se télécharge depuis le détail de ton ouverture, sur lebooster.fr.
Aucune connexion réseau n'est faite : tout le calcul tourne sur ta machine.`;

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(USAGE);
    return args.length === 0 ? 1 : 0;
  }
  if (args.includes('--self-test')) return selfTest();

  const path = args.find((a) => !a.startsWith('--'));
  if (!path) {
    console.error('Aucun fichier de preuve fourni.\n');
    console.error(USAGE);
    return 1;
  }

  let payload;
  try {
    payload = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    console.error(`Impossible de lire « ${path} » : ${e.message}`);
    return 1;
  }

  const { proof, snapshots, cards } = payload;
  if (!proof || !snapshots?.packRules || !snapshots?.pity) {
    console.error('Fichier incomplet : il faut { proof, snapshots: { packRules, pity }, cards }.');
    return 1;
  }
  if (payload.algoVersion && payload.algoVersion !== 'pf-v1') {
    console.error(
      `Ce vérificateur implémente pf-v1 ; la preuve annonce « ${payload.algoVersion} ».`
    );
    return 1;
  }

  let steps;
  try {
    steps = explain(proof, snapshots, cards ?? []);
  } catch (e) {
    console.error(`Rejeu impossible : ${e.message}`);
    return 1;
  }

  console.log(args.includes('--json') ? JSON.stringify(steps, null, 2) : render(steps, proof));
  return steps.allOk ? 0 : 1;
}

process.exit(main(process.argv));
