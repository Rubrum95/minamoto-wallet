# Minamoto Wallet — diseño, limitaciones y plan de seguridad

Este documento describe cómo construimos una wallet en Rust para enviar XOR
en **Minamoto** (mainnet de Iroha 3 / Sora Nexus, operado por Soramitsu),
las decisiones técnicas que tomamos, los compromisos de seguridad
**conscientes** que aceptamos en Phase 0, y el plan para cerrar esos huecos
con hardware externo (YubiKey 5C) en Phase 1.

> **Idioma:** Español. Apuntes técnicos, IDs y nombres de API en inglés
> porque así están en el código y en la documentación de Iroha 3.

## 1. Qué construimos

Un binario CLI nativo de Rust, single-executable, ad-hoc-firmado, que
corre desde Terminal en macOS y expone 7 subcomandos:

```
minamoto-wallet generate <label>     # nueva wallet (Ed25519 + I105 + 24 palabras BIP39)
minamoto-wallet restore  <label>     # recuperar desde mnemonic
minamoto-wallet pubkey   <label>     # mostrar pubkey + I105 sin Touch ID
minamoto-wallet balance  <label>     # consultar balances live de Torii
minamoto-wallet send-xor <label> --to <i105> --amount <X>
minamoto-wallet delete   <label>     # borrar wallet del Keychain + ciphertext
minamoto-wallet unlock-test <label>  # smoke-test del flow biométrico
```

### Stack

- **Lenguaje único:** Rust. Cero código en otros lenguajes.
- **Crypto on-chain:** `iroha_crypto` + `iroha_data_model` + `iroha_torii_shared`
  + `iroha_version` + `iroha_primitives` (path deps al checkout local de
  `hyperledger-iroha/iroha`, branch `i23-features`). No usamos un SDK
  parcheado — atacamos directamente los crates que el propio nodo usa
  para construir y validar transacciones, garantizando que los bytes que
  firmamos son exactamente los que el nodo verifica.
- **Almacenamiento de la clave:** P-256 keypair en macOS Keychain (login
  keychain file-based) + ECIES wrap del seed Ed25519 con AES-GCM.
  Detalles en §3.
- **HTTP client:** `reqwest` blocking, sin runtime async. POST
  `/transaction` con `Content-Type: application/x-norito` (Norito es el
  codec binario nativo de Iroha 3, derivado de SCALE).
- **Biometría:** `objc2-local-authentication` (FFI estable a
  `LocalAuthentication.framework` de Apple). Detalles en §4.
- **Backup:** mnemonic BIP39 24 palabras. NO es nativo de Iroha 3 — es
  nuestra red de seguridad off-chain en caso de pérdida del Keychain.

## 2. Por qué Iroha 3 / Minamoto es distinto a una blockchain "normal"

Antes de los riesgos de la wallet, contexto técnico que cualquiera que
revise este código necesita conocer:

1. **Account IDs no son addresses tipo Ethereum.** Son **I105** —
   strings con prefijo `sora` + caracteres katakana media-anchura
   codificando la pubkey + checksum. Ejemplo:
   ```
   sorauﾛ1PﾔpxﾛpQMketaﾅﾗUﾜVGZﾙQCmpﾐgzBﾃsXFkｼijKbｹ8B8A4C
   ```
   Los caracteres katakana son **literales**, no escapes Unicode.
   Cuidado con copy-paste entre apps con encoding distinto.

2. **El bridge cross-chain (Sora v2 → Minamoto) NO es trustless.** Es
   custodial:
   - Usuario hace `assets.burn` + `system.remark` en Sora v2 con un JSON
     `{type: "soraNexusXorClaim", recipient: "<i105>"}`.
   - **Soramitsu** monitoriza esos remarks, y submit un `Mint::Asset` en
     Minamoto firmado con una cuenta whitelisted on-chain
     (`nexus.fees.successful_claim_fee_exempt_authorities`).
   - El executor de Iroha NO valida que el burn realmente exista en v2;
     confía en el authority whitelisted. La integridad del bridge
     depende de que Soramitsu se comporte honestamente.
   - Si Soramitsu pausa el operator, los burns quedan en cola. Nuestro
     primer test de 1 XOR llevó >22h en cola al cierre de este doc.

3. **El chain de Minamoto se ha reseteado al menos 1 vez** (entre 27 y
   29 de abril 2026). El reset PRESERVA balances de los usuarios via un
   "genesis premint snapshot" — el operator copia los balances vivos al
   genesis del nuevo chain. Pero los `sora_v2_claim_tx_hash` de claims
   pre-reset se pierden.

4. **Iroha 3 firma con Ed25519 (RFC 8032 puro).** No SECP256K1 ni P-256.
   Esto es relevante para §3 — el Secure Enclave de Apple solo soporta
   P-256, así que **el seed Ed25519 NO PUEDE vivir literalmente dentro
   del chip SE**. Esa restricción física motiva todos nuestros
   compromisos de seguridad.

## 3. Cómo guardamos la clave (Phase 0)

### Modelo

```
                                                        ┌─ login.keychain (cifrado en disco
                                                        │   con tu password de macOS)
                                                        │
seed Ed25519 ─── ECIES encrypt ──▶ ciphertext           │
   (32 bytes)        ▲             (en JSON file        │
                     │              en App Support)     │
                     │                                  │
                P-256 pubkey ◀─────── P-256 keypair ◀───┘
                                       (software, NO en chip)
```

1. `generate` crea 32 bytes random vía `OsRng` (CSPRNG del kernel macOS).
2. Generamos un BIP39 mnemonic de 24 palabras desde esos 32 bytes →
   imprimimos UNA SOLA VEZ en stdout para que el usuario apunte en papel.
3. Generamos un P-256 keypair (software, NO Secure Enclave) y lo
   guardamos en login.keychain con label `minamoto-wallet:<label>`.
4. ECIES-encriptamos el seed Ed25519 contra el P-256 pubkey vía
   `SecKeyCreateEncryptedData(.. ECIESEncryptionCofactorVariableIVX963SHA256AESGCM ..)`.
   La operación es: ECDH efímero + X9.63-KDF + AES-GCM. Implementación
   nativa de Apple, no la nuestra.
5. Escribimos el ciphertext (~110 bytes) en
   `~/Library/Application Support/minamoto-wallet/<label>.json` con
   permisos 0600.
6. **Zeroize del seed** vía la crate `zeroize::Zeroizing<[u8;32]>`.

### Para firmar:

1. `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` →
   prompt de Touch ID (cuando macOS decide mostrarlo, ver §4).
2. Si OK, `SecItemCopyMatching` recupera el P-256 SecKey.
   Primera vez: macOS muestra diálogo "permite a esta app sin firma usar
   esta clave?" — el usuario teclea su password de macOS y elige
   "Permitir siempre" (autoriza el cdhash del binario, futuras llamadas
   no piden nada).
3. `SecKeyCreateDecryptedData(..)` descifra el ciphertext → seed plaintext
   en RAM por ~ms.
4. `iroha_crypto::PrivateKey::from_bytes(seed, Algorithm::Ed25519)` →
   `tx_builder.sign(&private_key)` produce `SignedTransaction`.
5. Drop del seed → zeroized.

### Qué protege este modelo

| Vector | ¿Defendido? | Cómo |
|---|---|---|
| Robo del Mac apagado, atacante no tiene tu password | ✓ | login.keychain está cifrado con clave derivada de tu password macOS; sin ese, el ciphertext es opaco. |
| Robo de TimeMachine backup | ✓ | El JSON con ciphertext sin la clave del Keychain es inservible. |
| Malware como tu usuario, sin root | ~ | Si autorizaste "Permitir siempre" para nuestro binario, otro proceso de tu usuario NO puede leer la clave (ACL del Keychain mira el cdhash). Pero un proceso CON el cdhash correcto sí puede. Como nuestro binario es ad-hoc-firmado, si el atacante puede leerlo del disco y ejecutarlo, ya está. |
| Sync a iCloud Keychain o entre Macs | ✓ | El item es `WhenUnlocked` (default) y NO `Synchronizable=true`. No sale de este Mac. |

### Qué NO protege (los huecos conscientes)

| Vector | ¿Vulnerable? | Por qué |
|---|---|---|
| **Atacante con tu password de macOS** + acceso físico al disco | ✗ | Puede descifrar `login.keychain-db` offline y extraer la P-256 privada. Después descifrar el ciphertext → seed Ed25519 → robar XOR. |
| **Cold boot RAM dump justo cuando firmas** | ✗ | El seed Ed25519 vive en RAM en plaintext durante ~milisegundos al construir la firma. Un atacante con acceso físico que congele la RAM puede leerlo. |
| **Malware con root + LLDB attached al proceso** | ✗ | Mismo problema: durante el window de firma, el seed es accesible vía debugger. |
| **Migration Assistant a otro Mac** | ✗ | El item `login.keychain-db` SÍ se transfiere via Migration Assistant (Apple lo migra entre Macs en setup inicial). Tu seed se mueve al nuevo Mac sin necesidad de Touch ID. |
| **Touch ID realmente per-firma** | parcial | Ver §4. macOS Sequoia reusa autenticaciones recientes — el prompt no siempre aparece. |

**Riesgo residual aceptado:** Phase 0 es seguridad equivalente a
`ssh-agent` con clave en disco cifrada por tu password de Mac. Suficiente
para pruebas de bridge con cantidades de test (1 XOR), inadecuado para
custodiar valor significativo a largo plazo.

## 4. Por qué no usamos el Secure Enclave de Apple ("el chip")

### El plan original

Usar el SE como gestor de claves end-to-end:
- Generar P-256 keypair INSIDE el chip con biometric ACL.
- Cada firma → Touch ID prompt nativo.
- La privada no sale nunca del chip.

### Por qué NO funciona para Iroha 3

1. **Iroha 3 requiere Ed25519, el SE solo hace P-256.** Imposible meter
   la firma Ed25519 en hardware Apple.

2. **Workaround — usar P-256 SE como "wrapping key":** generamos seed
   Ed25519 en software, lo encriptamos al pubkey de un P-256 que vive en
   el chip. Cada decrypt requiere Touch ID gestionado por el chip.

3. **PERO**: el comando `SecKeyCreateRandomKey(kSecAttrTokenID = SecureEnclave)`
   devuelve `errSecMissingEntitlement (-34018)` para binarios firmados
   ad-hoc en macOS Sequoia. **Apple cerró este path**: requiere o bien
   un Apple Developer ID ($99/año + verificación) o bien el flujo
   "Personal Team con provisioning profile" de Xcode (que caduca cada 7
   días y exige re-firmar).

4. **Verificado vía Apple DTS Quinn**: thread 728150 confirma
   explícitamente que el SE-tokenID requiere
   `com.apple.application-identifier` entitlement, sólo emitido por la
   infraestructura PKI de Apple. No hay forma de generar uno localmente.

### Y por qué tampoco usamos Keychain biometric ACL

Plan B: NO usar SE, sino guardar el item en login.keychain con
`kSecAttrAccessControl = [.biometryAny .or .devicePasscode]`. Cada
acceso al item dispararía Touch ID prompt nativo.

Esto también nos dio `errSecMissingEntitlement (-34018)`. Las ACL
biométricas en items genéricos del Keychain también requieren
entitlement Developer-ID-firmado.

### Lo que SÍ podemos hacer ad-hoc

1. **Item normal en login.keychain** (sin ACL biométrica) — funciona.
2. **`LAContext.evaluatePolicy` por separado** — funciona, pero...
3. **macOS reusa autenticaciones recientes**. Si has desbloqueado la Mac
   con Touch ID en los últimos minutos, `evaluatePolicy` puede pasar
   silenciosamente sin mostrar prompt. Resultado real: el Touch ID per
   firma NO está garantizado, depende del estado del sistema.

### Resumen del compromiso Phase 0

```
Lo que queríamos:           Lo que tenemos:
─────────────────           ────────────────
Touch ID per-firma          Macbook desbloqueado = wallet usable
Privada en chip             Privada en login.keychain (cifrada por password macOS)
Imposible exfiltrar         Exfiltrable con tu password de macOS
```

**Para custodia profesional necesitamos hardware externo.**

## 5. Plan Phase 1 — YubiKey 5C NFC

### Qué cambia

```
Phase 0:                                  Phase 1:
seed Ed25519 vive en RAM al firmar        seed Ed25519 vive en YubiKey, NUNCA en RAM
└─ vulnerable a RAM dump                  └─ inmune a RAM dump

Touch ID nativo no garantizado            Tap físico al botón dorado del YubiKey
└─ Mac desbloqueado = wallet usable       └─ Cada firma = tap explícito
                                              + PIN opcional 4-8 dígitos

Privada extraíble si tienen tu password   Privada NO extraíble por software
└─ Mac password protege                   └─ Hardware-aislada, requiere
                                              romper el chip físicamente
```

### Cómo

YubiKey 5 desde firmware **5.7** (mayo 2024) soporta Ed25519 nativamente
en su PIV applet (PKCS#11). El flujo:

1. Compras YubiKey 5C NFC (~70€ en Amazon España, 2-3 días envío).
2. Conectas al USB-C del Mac.
3. Generamos el keypair Ed25519 ONBOARD del YubiKey:
   ```bash
   yubico-piv-tool -a generate -s 9c -A ED25519 \
     --pin-policy=once --touch-policy=always
   ```
   - `slot 9c` = "Digital Signature" (uso correcto para wallets).
   - `--touch-policy=always` = OBLIGA tap por cada firma.
   - `--pin-policy=once` = PIN una vez por sesión USB.
4. Extraemos el pubkey del YubiKey → derivamos el I105 → es la nueva
   wallet en Minamoto (NOTA: distinto I105 que la wallet Phase 0
   porque es otra clave; hay que migrar el XOR con un Transfer ISI
   normal de la vieja a la nueva).
5. Para firmar:
   - Wallet construye `TransactionPayload`.
   - Calcula `Blake2bVar32(NoritoEncode(payload))` con `LSB|=1`
     (invariante de Iroha sobre el hash a firmar).
   - Envía hash al YubiKey vía `pkcs11` o `yubikey-rs`.
   - YubiKey solicita PIN (si no está cacheado) + tap del botón.
   - YubiKey devuelve 64 bytes de firma Ed25519.
   - Wallet ensambla `SignedTransaction` y POST a Torii.

### Coste de implementación

Reemplazar exclusivamente el módulo `secure_enclave.rs` por un
`yubikey.rs`. El resto del código (transfer.rs, torii.rs, wallet.rs,
balance.rs) **NO cambia** — solo cambia la implementación detrás del
trait "give me a 64-byte Ed25519 signature for this hash". Por eso
diseñamos así desde el principio: el módulo cripto es el único acoplado
al hardware.

Estimado: ~1 día de implementación + tests en Taira testnet antes de
mover XOR de verdad.

## 6. Por qué Rust único, no Rust + Swift

Consideramos una variante con un helper Swift de ~50 líneas usando
`CryptoKit.SecureEnclave.P256` (la API que `age-plugin-se` de Filippo
Valsorda usa con éxito en producción). Esa API SÍ funciona ad-hoc y SÍ
da Touch ID nativo per operación.

Lo descartamos porque:

1. Introduce una segunda toolchain (Swift) en el repo.
2. Requiere FFI Rust↔Swift via `swift-bridge` o subprocess (más superficie).
3. La ventaja real (SE-resident wrapping key) sigue sin proteger contra
   los vectores que importan (RAM dump al firmar, acceso a disco con
   password de macOS). El upgrade real es YubiKey, no Swift+SE.
4. Coherencia con el resto del repo `sora/` que es 100% Rust.

## 6.bis. Exposición de la mnemonic en el front-end web

A partir de la versión con `minamoto-wallet ui`, el wallet sirve un
front HTML local en `127.0.0.1:7825`. El backend HTTP está embebido en
el mismo binario y comparte proceso con la lógica de firma — la seed
NUNCA viaja por HTTP en plaintext (ni cifrada). El navegador solo
recibe metadata pública: I105, pubkey, balance, hashes de tx.

**EXCEPCIÓN crítica:** durante el flow de generación de wallet, la
mnemonic BIP39 (24 palabras, equivalente al seed) se devuelve en el
body JSON de `POST /api/generate` para que el usuario la vea UNA vez
y la apunte en papel. Mientras la card de mnemonic está abierta,
las palabras viven en:

- `Network` panel de DevTools (response body cacheado por el
  navegador hasta navegación o cierre de pestaña).
- DOM (`<div class="seed-word">` × 24).
- JS heap (parsed response object, hasta GC).

**Mitigación:** al pulsar `Continue` (acknowledge), el front:
1. Limpia los nodos DOM de las palabras explícitamente.
2. Llama `window.location.reload()` que descarta el fetch cache,
   los timers, y vacía la network panel del documento.

**Riesgo residual:** un usuario con DevTools abiertos durante la card
puede leer la mnemonic. Una extensión de browser con permiso `<all_urls>`
puede leer el DOM o el response body. Para wallets reales, **la
recomendación operativa es no instalar extensiones en el navegador
donde corres este wallet** — usa un perfil dedicado o un browser
secundario.

## 7. Orden estricto de defensa contra ataques (Phase 0 → Phase 1)

| Vector | Phase 0 (hoy) | Phase 1 (YubiKey) |
|---|---|---|
| Disco robado, sin tu password | ✓ | ✓ |
| Disco + tu password | ✗ | ✓ |
| Migration Assistant a otro Mac | ✗ | ✓ (key chip-bound, no migra) |
| Cold boot RAM dump al firmar | ✗ | ✓ (seed nunca en RAM) |
| Malware root + LLDB | ✗ | ✓ (firma onboard) |
| Coerción "dedo dormido" | parcial | ✓ (botón táctil capacitivo, no biométrico) |
| Soramitsu pausa el bridge | ✗ | ✗ (problema de protocolo, no de wallet) |

## 8. Riesgos NO de la wallet — del bridge

Independientemente de la calidad de la wallet, el bridge Sora v2 →
Minamoto añade un riesgo de protocolo:

1. **El operador (Soramitsu) decide cuándo procesar tu burn.** Si paran
   el bot por mantenimiento, deploy roto, o decisión política, los burns
   quedan colgados.

2. **No hay timeout on-chain ni mecanismo de "revertir burn".** Una vez
   quemas en v2, el XOR está destruido. Si Soramitsu nunca te procesa,
   tu XOR está perdido.

3. **No hay slashing del operator** ni penalización on-chain por SLA.

4. **El authority del operator está hardcoded** en la lista
   `nexus.fees.successful_claim_fee_exempt_authorities`. Cambiarlo
   requiere un upgrade del runtime.

Esto NO se arregla con YubiKey. Es un problema arquitectónico del bridge
que requiere o bien (a) descentralizar el operator (multi-sig de
validators), o (b) un protocolo de proof-of-burn verificable on-chain en
Minamoto (zkProof del estado de sora v2).

## 9. Cómo verificar que la wallet funciona sin tocar XOR real

```bash
# Build (una vez, ~5 min primer compile, después incremental ~1 min)
cd minamoto-wallet
cargo build --release
codesign -s - --force ./target/release/minamoto-wallet

# Crea wallet de test
./target/release/minamoto-wallet generate test
# Apunta el i105 que imprime; la mnemonic puedes ignorarla (test).

# Deriva pubkey + i105 sin Touch ID (lee del JSON)
./target/release/minamoto-wallet pubkey test

# Smoke-test del biometric flow (sin enviar tx)
./target/release/minamoto-wallet unlock-test test
# Esperado: prompt de Touch ID + "OK — seed unwrapped successfully"

# Borra
./target/release/minamoto-wallet delete test
rm ~/Library/Application\ Support/minamoto-wallet/test.json
```

Para test cross-chain real:
1. `generate prod` con tu wallet real.
2. Apunta la mnemonic en papel.
3. Toma el `i105` y lo usas como recipient en
   `app.sora.org` → bridge a Minamoto → quema 1 XOR.
4. Espera al operator (cola actual ~22h).
5. `balance prod` para verificar.
6. `send-xor prod --to <otro_i105> --amount 0.1` para test final.

## 10. Lecciones para diseñar wallets en macOS sin Apple Developer

1. **El Secure Enclave de Mac NO es una caja libre.** Apple lo
   condiciona a tener Developer ID emitido por su PKI. La narrativa
   "tu Mac tiene un chip de seguridad como una HSM" es matizable: solo
   accesible si pagas o usas el flujo Personal Team con re-firma
   semanal.

2. **Las ACL biométricas en Keychain también requieren entitlement.**
   No son "free for all".

3. **`LocalAuthentication.framework` SÍ es accesible ad-hoc** pero su
   reuso de auth reciente significa que el prompt no es garantizado per
   operación.

4. **`age-plugin-se` (Filippo Valsorda) demuestra que con Swift +
   CryptoKit es posible**, pero introduce dependency Swift y solo
   protege ECDH/decrypt; el seed Ed25519 sigue tocando RAM en cualquier
   wallet basada en él.

5. **Si quieres wallet seria en Mac → YubiKey con firmware 5.7+, end of
   story.** Es el único path que cierra todos los vectores realistas
   sin pelear con la PKI de Apple.

## 11. Referencias verificadas

- Apple DTS Quinn — thread 728150: SE token-ID requiere
  `com.apple.application-identifier`. https://developer.apple.com/forums/thread/728150
- Apple DTS Quinn — thread 740164: confirma que NO necesitas pagar $99,
  pero SÍ necesitas un App ID con provisioning profile.
  https://developer.apple.com/forums/thread/740164
- Apple — Signing a Daemon with a Restricted Entitlement
  (.app + embedded.provisionprofile flow):
  https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement
- age-plugin-se (Filippo Valsorda / Remko): https://github.com/remko/age-plugin-se
- Iroha 3 source (i23-features): `feina/sora/iroha-source/iroha`
- YubiKey PIV Ed25519 support (firmware 5.7+):
  https://www.yubico.com/blog/ed25519-and-x25519-comes-to-yubikey/
- Iroha 3 cross-chain claim executor logic:
  `iroha_core/src/executor.rs:500-562` (whitelist authority check)

---

**Última actualización:** 2026-04-30. Phase 0 desplegado y verificado.
Phase 1 (YubiKey) pendiente de hardware.
