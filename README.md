# Vérificateur de tirage LeBooster

Refais toi-même le calcul d'une ouverture LeBooster, sur ta machine, sans nous faire confiance.

Un seul fichier, **aucune dépendance** : `verify-lebooster.mjs` n'utilise que `node:crypto`, qui
fournit SHA-256 et HMAC-SHA-256. Tu peux le lire en entier avant de l'exécuter, c'est le but. Il ne
contacte aucun serveur et n'écrit rien sur ton disque.

```bash
node verify-lebooster.mjs ma-preuve.json
```

Le programme affiche **chaque étape intermédiaire** du calcul, et sort avec le code `0` si la preuve
est valide, `1` sinon.

## Ce dont tu as besoin

1. Node.js 18 ou plus récent. Rien d'autre à installer.
2. Ta preuve, au format JSON, à télécharger depuis le détail de ton ouverture sur lebooster.fr
   (bouton « Télécharger la preuve »).

Pour essayer tout de suite sans compte, un exemple est fourni :

```bash
node verify-lebooster.mjs example-proof.json
```

## Les trois choses que ce programme vérifie

**1. L'engagement n'a pas été changé après coup.** Avant chaque ouverture, LeBooster publie
`commit = SHA-256(graine serveur)` sans révéler la graine. Après l'ouverture, la graine est révélée.
Le programme recalcule l'empreinte et la compare. Comme SHA-256 n'est pas inversible, publier une
empreinte puis en changer la graine est impossible sans que ce test le voie.

**2. Le tirage dérive bien des deux graines.**
`draw = HMAC-SHA-256(clé = graine serveur, message = "graine client:nonce")`. Ta graine client est
générée par ton navigateur et LeBooster ne la connaît pas au moment de s'engager : le résultat ne
peut donc pas être choisi à l'avance.

**3. Le tirage donne exactement les cartes annoncées.** Le programme rejoue le passage du tirage aux
cartes : la bande de rareté de chaque slot, l'anti-malchance, puis le choix de la carte dans le pool
figé. Toutes les valeurs intermédiaires sont affichées.

## L'algorithme, en détail

Versions rejouables : `pf-v1` et `pf-v2`. Tout ce qui suit fait partie du contrat de vérification : une seule de ces valeurs
qui change impose une nouvelle version d'algorithme.

### Primitives

| Étape      | Formule                                                                               |
| ---------- | ------------------------------------------------------------------------------------- |
| Engagement | `commit = hex(SHA-256(graine_serveur))`, la graine étant décodée depuis l'hexadécimal |
| Tirage     | `draw = HMAC-SHA-256(clé = graine_serveur, message = UTF-8("graine_client:nonce"))`   |
| Sous-flux  | `stream(draw, label, i) = HMAC-SHA-256(clé = draw, message = UTF-8("label:i"))`       |
| Entier     | `u32` = les 4 premiers octets, gros-boutiste                                          |
| Réel       | `r = u32 / 2^32`, donc dans `[0, 1)`                                                  |

La graine client est une chaîne **opaque**, utilisée telle quelle, jamais ré-encodée. Le nonce est
écrit en décimal. Le séparateur est un `:` littéral.

### Des cartes à partir du tirage

Les slots sont évalués par **`slot.index` croissant** — c'est l'ordre normatif, distinct de l'ordre
d'affichage. Pour le slot en position d'évaluation `p` :

1. **Bande de rareté.** `r = float01(stream(draw, "rarity", p))`. Les poids du slot sont normalisés
   en fonction de répartition cumulée, parcourue **dans l'ordre du snapshot** ; la première bande
   dont le cumul dépasse `r` est retenue.
2. **Anti-malchance.** Évaluée une seule fois par ouverture, sur le slot d'index le plus élevé. Si la
   bande tirée atteint déjà le rang garanti, le compteur repart à zéro sans rien forcer. Sinon, si
   `compteur + 1 ≥ seuil`, la bande garantie est forcée. Sinon le compteur avance d'un cran. Elle ne
   dégrade jamais une rareté.
3. **Carte.** Dans le pool **restant** de cette bande, de taille `n`, par échantillonnage avec rejet :
   `limite = floor(2^32 / n) × n`, puis pour `i = 0, 1, 2…` on tire `v = u32(stream(draw, "card:p", i))`
   jusqu'à `v < limite`, et l'index vaut `v mod n`. Ce rejet supprime le biais du modulo quand
   `2^32` n'est pas divisible par `n`. Chaque rejet consomme un `i` et reste donc reproductible.
4. **Avec ou sans remise, selon la version.** En `pf-v2` la carte choisie reste dans le pool : une
   même carte peut sortir plusieurs fois dans une ouverture. En `pf-v1` elle en était retirée avec
   un décalage (jamais un échange avec la dernière), de sorte qu'une carte ne sortait qu'une fois.
   La borne de rejet se calcule sur la taille du pool lu, donc les deux versions divergent dès le
   deuxième slot d'un même palier : une preuve se rejoue toujours avec **sa** version.

### Le pool figé

Si ta preuve porte un `poolDigest`, le programme le recalcule :
`hex(SHA-256(JSON du pool ordonné, clés de rareté triées))`. L'ordre des cartes à l'intérieur d'une
rareté **est** l'ordre de tirage et n'est pas retrié. Ce test prouve que le pool qu'on te donne à
vérifier est bien celui qui était figé au moment du tirage.

### Normalisation des raretés

Comparer « Rare Illustration spéciale » et « rare illustration speciale » doit donner le même rang :
décomposition NFD, suppression des diacritiques, minuscules, espaces compactés. Une rareté qui ne
correspond à aucun alias du barème vaut le rang 0.

## Format du fichier de preuve

```jsonc
{
  "algoVersion": "pf-v1",
  "proof": {
    "commit": "…", // empreinte publiée AVANT l'ouverture
    "serverSeed": "…", // graine serveur, révélée APRÈS
    "clientSeed": "…", // ta graine, générée par ton navigateur
    "nonce": 0, // ton compteur d'ouverture
    "draw": "…", // optionnel : le tirage publié, vérifié s'il est là
    "poolDigest": "…", // optionnel : empreinte du pool figé
  },
  "snapshots": {
    "packRules": {
      "slots": [{ "index": 0, "odds": [{ "rarity": "Common", "weight": 10000 }] }],
      "pools": { "Common": ["carte-1", "carte-2"] },
      "rankBareme": [{ "rank": 1, "aliases": ["Common", "Commune"] }],
    },
    "pity": { "counter": 0, "threshold": 15, "guaranteedRarity": "Ultra Rare" },
  },
  "cards": [{ "slot": 0, "rarity": "Common", "cardId": "carte-1" }],
}
```

Seul `cards` est facultatif : sans lui, le programme recalcule le tirage et les cartes sans les
comparer à rien.

## Vérifier le vérificateur

```bash
node verify-lebooster.mjs --self-test
```

Rejoue cinq vecteurs de référence figés (`kat.json`) qui couvrent le cas nominal, une collision de
raretés, un déclenchement d'anti-malchance, un rejet d'échantillonnage et un ordre d'affichage
différent de l'ordre d'évaluation. Ces vecteurs sont les mêmes que ceux du moteur de production.

Ils servent aussi de garde-fou de notre côté : un test du dépôt LeBooster exécute **ce fichier même**
sur ces vecteurs et compare chaque valeur intermédiaire à celles du moteur qui tire réellement les
cartes. Modifier l'algorithme sans reporter la modification ici casse notre intégration continue.

## Ce que ce programme ne prouve pas

Il prouve que le tirage qu'on t'a annoncé découle bien des graines engagées, et rien d'autre. Il ne
dit pas si les **taux annoncés** sont ceux qui ont été configurés, ni si le **pool** contient ce
qu'il devrait : ces deux points se lisent sur la fiche du booster, qui publie les taux annoncés face
aux taux réellement observés.

Il ne dit pas non plus que ta graine client a été tirée au hasard — c'est ton navigateur qui la
génère, et tu peux la remplacer par ce que tu veux avant d'ouvrir. C'est précisément ce qui rend le
schéma solide : nous ne pouvons pas la deviner au moment de nous engager.

## Licence

MIT.
