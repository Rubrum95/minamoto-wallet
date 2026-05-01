# Minamoto Wallet — ZK roadmap

Plan honesto y por fases para integrar transacciones confidenciales
(Shield / ZkTransfer / Unshield) en `minamoto-wallet`. Estado actual:
**stubbed** — los subcomandos `shield` y `unshield` existen y aceptan
argumentos, pero abortan con un mensaje informativo. La razón es que
hay piezas criptográficas concretas que faltan; este documento las
enumera, en orden de coste creciente.

## Recap del modelo on-chain

Iroha 3 expone tres ISIs en `iroha_data_model::isi::zk` (verificado en
nuestro checkout local i23-features):

```rust
pub struct Shield {
    asset: AssetDefinitionId,
    from:  AccountId,
    amount: u128,
    note_commitment: [u8; 32],     // ← Poseidon hash
    enc_payload: ConfidentialEncryptedPayload,  // ← AEAD a viewing key
}

pub struct ZkTransfer {
    asset: AssetDefinitionId,
    inputs:  Vec<[u8; 32]>,        // ← nullifiers gastados
    outputs: Vec<[u8; 32]>,        // ← commitments nuevos
    proof: ProofAttachment,        // ← Halo2-IPA
    root_hint: Option<[u8; 32]>,   // ← Merkle root hint
}

pub struct Unshield {
    asset: AssetDefinitionId,
    to: AccountId,
    public_amount: u128,
    inputs: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
    proof: ProofAttachment,
    root_hint: Option<[u8; 32]>,
}
```

XOR en Minamoto (asset def `6TEAJqbb8oEPmLncoNiMRbLEK6tw`) tiene
configurado:

```json
"confidential_policy": { "mode": "Convertible", "vk_set_hash": "..." },
"metadata": {
  "zk.policy": {
    "allow_shield": true,
    "allow_unshield": true,
    "vk_transfer": "halo2/ipa::vk_transfer",
    "vk_unshield": "halo2/ipa::vk_unshield"
  }
}
```

es decir, las verifying keys (VK) del executor están establecidas,
las transiciones shield/unshield están permitidas. **Falta nuestro
lado**: generar las pruebas correctas.

## Pieza por pieza — en orden de complejidad

### 1. Note scheme (commitment)

**Pregunta abierta:** ¿qué función usan los notes de Minamoto para el
commitment? La hipótesis estándar (sigue a Aztec / Sapling) es:

```
commitment = Poseidon(value, recipient_viewing_pubkey, nonce, [more...])
```

Pero los parámetros Poseidon (rate, capacity, S-box rounds, MDS matrix)
son específicos del setup. Hay que verificar:

- `iroha_zkp_halo2/src/poseidon.rs` para los params (rate/capacity exactos).
- Si Iroha 3 sigue una variante estándar (Vesta + Pasta? bn256?) o
  custom.
- Si el `confidential_policy.vk_set_hash` codifica los params.

**Coste**: medio. Investigación de unos días + tests dummy con notas
vacías para confirmar que el commitment generado coincide con el que
genera el cliente Iroha oficial (cuando aparezca).

### 2. Viewing-key derivation

Las notas se cifran al `viewing_pubkey` del recipient. Convención
Sapling: `viewing_key = SK_v` (separada del spending key Ed25519) +
`viewing_pubkey = JubJub.G * SK_v`.

**Pregunta abierta:** ¿usa Iroha JubJub, Curve25519, o algo más simple?

- `iroha_data_model::isi::zk::ConfidentialEncryptedPayload` tiene los
  campos del envelope (`pk_recipient`, `nonce`, `ciphertext`).
- Hay que decodificar los txs `Shield` ya commited en chain (el genesis
  premint en mn block 1 los tiene) para inferir los tamaños de los
  campos → confirma la curva.

**Coste**: bajo si Curve25519 (ya lo tenemos vía iroha_crypto), medio
si JubJub o BLS (hay que añadir crate específico).

### 3. Encryption scheme del payload

Convención típica: `ChaCha20-Poly1305` o `AES-GCM` con clave derivada
vía X25519 ECDH(ephemeral_sk, recipient_viewing_pk) → HKDF.

**Pregunta abierta:** ¿qué AEAD? ¿qué KDF? ¿hay metadata adicional?

Mismo método de descubrimiento: decodificar payloads on-chain reales.

**Coste**: bajo. Una vez sabido el algoritmo, las crates `chacha20poly1305`
o `aes-gcm` ya están en crates.io con bindings limpios.

### 4. Shield real (sin proof, solo commitment + payload)

**Buena noticia:** `Shield` NO requiere proof Halo2 según el ISI struct.
Tiene `note_commitment` + `enc_payload`, no `proof`. El executor
probablemente solo verifica:
- la cuenta `from` tiene balance público suficiente,
- la cantidad es positiva,
- el commitment está bien formado (longitud 32 bytes — formato Poseidon
  el chain lo verifica internamente al añadirlo al árbol).

Si esto se confirma, **Shield es factible sin proving keys ni circuits**.
Solo necesitamos:
1. Generar nuestro propio note (random nonce + value + viewing_pubkey).
2. Calcular Poseidon commitment.
3. Cifrar el payload con AEAD a NUESTRO viewing_pubkey (porque somos el
   recipient).
4. Construir el `Shield` ISI y firmarlo.

**Estimado**: 3-5 días si descubrimos rápido los detalles 1-3.

### 5. ZkTransfer / Unshield (proof Halo2-IPA real)

Aquí está el coste alto. Para gastar una nota:

a) **Indexar el shielded ledger.** Suscribirnos a eventos
`ConfidentialTransferred` desde el block donde recibimos la primera
nota, mantener un Merkle tree local con los commitments del chain.

b) **Calcular nullifier:** función PRF(viewing_sk, position_in_tree)
o similar. Lo que el chain rechazará si ya está en su nullifier set.

c) **Construir witness:** value, viewing_sk, nonce, Merkle path desde
nuestro commitment hasta el root del árbol.

d) **Ejecutar el prover Halo2-IPA:** usar `iroha_zkp_halo2::IpaProver`
con el circuit de `Unshield` (o `ZkTransfer`). Esto necesita las
proving keys (PK) — ficheros de **100-500 MB** que Iroha probablemente
distribuye fuera del chain.

e) **Adjuntar el proof** al ISI vía `ProofAttachment`.

**Pregunta crítica abierta:** ¿de dónde sacamos las PK?

Opciones:
- Compilar nosotros el circuit en `iroha_zkp_halo2` y derivar las PK
  desde el setup ceremony (cualquier setup determinista, dado que el
  chain ya tiene el VK fijado). Esto requiere reproducir el setup
  exactamente como Soramitsu lo hizo (mismo random tape).
- Pedir a Soramitsu las PK (probable: están públicas en algún release
  artifact).
- Reverse-engineer desde un wallet de referencia que sí las use (si
  publican su CLI con PK embebidas).

**Estimado**: 2-3 semanas, dominado por (a) indexer del shielded
ledger y (d) integración Halo2 con las PK correctas.

## Lo que vamos a hacer ahora

**Phase 0 (CONGELADO mientras Soramitsu desbloquea el burn):**
- CLI stubs `shield` / `unshield` que abortan con mensaje informativo.
- Hooks listos en `main.rs` para enchufar la lógica real.

**Phase 1 (cuando tengamos XOR transparente operativo):**
- 4.1: Implementar Shield real (commitment + payload sin proof).
- Test: shield 0.1 XOR de tu balance; verificar que el chain accept.

**Phase 2 (cuando shield funcione):**
- 4.2: Indexer local del shielded ledger (suscripción WebSocket o
  poll a `/v1/explorer/instructions?kind=Shield&kind=ZkTransfer`).
- 4.3: Cálculo de nullifiers y Merkle paths.

**Phase 3 (proof generation):**
- 4.4: Conseguir las PK de Halo2-IPA para `unshield` y `zk_transfer`.
- 4.5: Wiring con `iroha_zkp_halo2::IpaProver`.
- 4.6: Pruebas extensas en Taira (testnet) antes de Minamoto.

## Riesgos del proyecto Phase 1-3

1. **PK distribution**: si Soramitsu no distribuye los PK públicamente,
   el camino auto-soberano de ZK es bloqueado. Habría que generar PK
   propios y demostrar al chain que verifican igual (no se puede sin
   conocer el setup ceremony).

2. **Note scheme indocumentado**: si los parámetros Poseidon son custom
   y no están en la documentación pública, descubrirlos requiere reverse
   engineering del binario Iroha node.

3. **Shielded ledger growth**: el Merkle tree crece linealmente. Mantener
   índice local consume disco; sincronizarlo desde cero requiere re-leer
   todos los blocks con eventos ZK.

4. **Halo2-IPA proof time**: generar un proof completo en Mac M1 puede
   ser 5-30 segundos según tamaño del circuit. UX que tener en cuenta.

## Referencias verificadas

- `iroha_data_model/src/isi/zk.rs` (ISI struct definitions)
- `iroha_data_model/examples/export_confidential_wallet_fixtures.rs`
  (build patterns con dummy proofs)
- `iroha_zkp_halo2/src/ipa.rs` (`IpaProver::prove(...)` API)
- `iroha_zkp_halo2/src/poseidon.rs` (commitment hash params)
- `iroha_core/src/executor.rs` (server-side validation, busca
  `verify_proof`)

---

**Última actualización:** 2026-04-30 (post-deep-dive). Phase 1 (Shield)
**implementada y compilada** — ver §A abajo. Phase 2 (Unshield/ZkTransfer)
sigue requiriendo el indexer del shielded ledger + integración del prover
Halo2-IPA. Las proving keys NO son un bloqueante: descubrimos que el
runtime las regenera vía `keygen_pk` con `k=7` (transparent setup, milisegundos).

## §A. Estado real Phase 1 — Shield IMPLEMENTADO

Después de un deep-dive en `iroha_core/src/zk/confidential_v2.rs`
descubrí que la note-scheme **NO es Poseidon estándar**. Es una
"pseudo-Poseidon" simplificada (S-box x⁵ con `2·l⁵ + 3·r⁵` mixing) sobre
**Pasta Fp** (no BN254 ni JubJub). La fórmula entera:

```
asset_tag    = pasta_repr( hash_to_scalar("iroha.confidential.v2.asset_tag",  trimmed_asset_def_id) )
spend_scalar = hash_to_scalar("iroha.confidential.v2.spend_scalar", spend_key_bytes)
diversifier  = Scalar::ONE  (default)
owner_tag    = pasta_repr( poseidon_pair(spend_scalar, diversifier) )

rho_scalar      = hash_to_scalar("iroha.confidential.v2.note_rho", rho_bytes)
amount_scalar   = scalar_from_u128(amount)

note_commit_sc  = poseidon_pair(amount,
                    poseidon_pair(rho, poseidon_pair(owner_tag, asset_tag)))
note_commitment = pasta_repr_le_bytes(note_commit_sc)   // 32 bytes
```

con `poseidon_pair(l, r) = 2·(l+7)⁵ + 3·(r+13)⁵` en Pasta Fp.

`hash_to_scalar(label, parts)` usa Blake3 con counter loop hasta que el
digest sea canónico para Pasta Fp.

### Lo implementado (en `minamoto-wallet`)

- `src/zk_v2.rs` — port byte-a-byte de las funciones públicas de
  `iroha_core::zk::confidential_v2` (deps: `pasta_curves`, `ff`, `blake3`).
  5/5 unit tests passing.
- `src/shield.rs` — builder del Shield ISI:
  1. Resuelve I105 + AssetDefinitionId.
  2. Touch ID gate via `wallet::unlock_seed`.
  3. Deriva `owner_tag` desde el seed.
  4. Genera `rho` random.
  5. Calcula `note_commitment` con la fórmula upstream.
  6. Construye Shield ISI con `enc_payload = ConfidentialEncryptedPayload::default()`
     (zeros — ver §B sobre el trade-off).
  7. Norito-encode + sign con Ed25519 + POST a Torii.
  8. Persiste el `LocalNote` en el JSON file del wallet.
- `src/storage.rs` — `WalletRecord.notes: Vec<LocalNote>` + `append_note()`.
- CLI: `minamoto-wallet shield <label> <amount>` operativo.
- UI: card "Shield XOR" + "Local shielded notes" en la web local.
- Endpoints: `POST /api/wallet/<label>/shield` + `GET /api/wallet/<label>/notes`.

### §B. Trade-off del payload Phase 1

El `ConfidentialEncryptedPayload` se envía como `default()` (zeros). Esto
significa:

- **Lo que pierdes:** scanning automático del chain. Otro wallet con
  view-key NO podrá descubrir esta nota desde el explorador. Si pierdes
  el `LocalNote` JSON local, la nota queda **on-chain pero no spendable**
  (el `rho` y `owner_tag` desaparecen contigo).

- **Lo que mantienes:** el `note_commitment` está bien formado, así que
  cuando Phase 2 (Unshield/ZkTransfer) esté listo, las notas sí podrás
  gastarlas usando el LocalNote como witness.

Encryption recipe correcta (X25519 + KDF + XChaCha20-Poly1305) está
**especificada en docs pero no implementada en el repo iroha**. El SDK
Swift recibe el payload como input opaco. Para implementarla bien
necesitamos preguntarle a Soramitsu el KDF exacto y el AAD.

### §C. Validación pendiente (cross-check)

El port `derive_confidential_note_v2` debe ser bit-idéntico al upstream.
Self-tests pasan (5/5). El último cross-check honesto solo se puede
hacer **submitiendo un Shield real** y verificando que:
1. El chain acepta la tx (commitment longitud y encoding correctos).
2. Phase 2 logra gastar la nota (commitment derivable desde witness
   matching la lookup en el Merkle tree).

Bloqueante: el operator de Soramitsu sigue sin procesar el burn cross-
chain del usuario, así que no tenemos XOR para hacer Shield real.

## Phase 2 — qué falta (orden actualizado)

1. **Event-stream listener** (~3-5 días): suscripción al endpoint
   `/v1/events` de Torii filtrando `ConfidentialEvent::{Shielded, Transferred,
   Unshielded}`. Cada evento append commitments al árbol local.
2. **Local Merkle tree** (~2 días): port de
   `compute_confidential_merkle_path_v2` usando el mismo `poseidon_pair`
   simplificado, profundidad 16.
3. **Halo2 prover integration** (~1-2 semanas): añadir dep
   `halo2_proofs` con feature mínimo. Reusar circuits via `keygen_pk` +
   `create_proof`. PERO: hay que verificar que los circuit IDs y witness
   layouts coinciden con lo que el chain espera. Riesgo medio.
4. **Unshield CLI + UI** (~2 días): construir `Unshield` ISI usando los
   notes locales como inputs.
5. **ZkTransfer privado** (~3-5 días): igual que Unshield pero con
   outputs cifrados al recipient (necesita encryption recipe ARRIBA).
