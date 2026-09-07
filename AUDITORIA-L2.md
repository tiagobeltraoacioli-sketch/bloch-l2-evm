<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Auditoria profunda — `bloch-l2-evm` (camada de execução do Bloch EVM L2)

| | |
|---|---|
| **Alvo** | crate `bloch-l2-evm` v`0.0.0-scaffold`, commit `4f0882e` (branch `main`), 2.665 linhas de Rust em `src/` |
| **Data** | 2026-09-07 |
| **Método** | leitura integral por 10 lentes independentes, provas de conceito executadas, deduplicação, reprodução independente de cada achado e painel adversarial de céticos (60 agentes de verificação), verificação factual dos itens informativos |
| **Toolchain** | rustc 1.94.1 / cargo 1.94.1; `revm 41.0.0`, `alloy-trie 0.9.5`, `alloy-primitives 1.6.1`, `alloy-rlp 0.3.16`, `ruint 1.19.0`, `nybbles 0.4.8` (conforme `Cargo.lock`, 292 pacotes) |
| **Baseline** | `cargo test --all-features`: 40 testes, 40 aprovados (o README afirma 22) |
| **Anexo executável** | `tests/audit_regressions.rs` — um módulo por achado; os achados corrigidos têm testes ativos, os ainda abertos ficam `#[ignore]` (`cargo test --test audit_regressions -- --ignored` lista-os) |
| **Status** | **Adendo (mesma data):** os itens P0 da seção 8 foram corrigidos; ver §0 abaixo |

> **Posicionamento.** O próprio crate se declara *scaffold, não auditado, não é um L2 funcional* e diz que tudo é *testnet / valor zero*. Esta auditoria avalia o código **contra o que ele afirma garantir** (emissão zero, "nunca queima", raiz de estado keccak‑MPT correta, caminho de prova stateless "correct‑or‑error") **e contra o que uma função de transição de estado (STF) de L2 real precisa garantir** (atomicidade, solidez das provas, paridade de consenso com Ethereum Cancun, robustez contra entradas maliciosas). Limitações *documentadas* pelo crate continuam sendo achados quando representam lacunas de solidez para o desenho pretendido; o relatório indica quando esse é o caso. A ausência dos componentes explicitamente *stubbed* (nó Reth, RPC `eth_*`, txpool, guest SP1) **não** é tratada como achado.

---

## 0. Adendo — correções P0 aplicadas

Após a entrega do relatório, os itens **P0** da seção 8 foram implementados no mesmo branch (commit seguinte ao relatório). Resumo do que mudou e de como foi verificado:

| Achado | Correção | Verificação |
|---|---|---|
| **C01** | `execute_block` valida a entrada inteira antes de tocar o estado, aplica o bloco a uma **cópia de trabalho** e só substitui `state` em `Ok`; em qualquer `Err` o estado do chamador é byte‑idêntico ao pré‑bloco. O `mem::take` sem restauração foi eliminado (`run_block` consome e devolve o banco). | `executor::tests::evm_errors_leave_state_unchanged`, `block_gas_limit_exceeded_is_rejected_without_touching_state`; `tests/audit_regressions.rs::c01` |
| **C02** | Depósitos passam pela mesma cópia atômica: um bloco rejeitado não deixa nenhum mint aplicado nem contado; duplicatas dentro do bloco são `DuplicateDeposit` na validação pura. | `blob_transactions_are_rejected_at_the_sequencer_without_touching_state`; `c02` |
| **C03 / C25** | Whitelist de tipos `{0,1,2}` (`SUPPORTED_TX_TYPES`), `UnsupportedTxType` para os demais, `InconsistentTxEnv` para envs cujo tipo não bate com os campos; o roteamento usa `Transaction::effective_gas_price` do próprio revm e credita `min(effective, basefee) × gas`. | `unsupported_tx_types_are_rejected_and_never_inflate_supply`; `c03`, `c25` |
| **C10 / C18 / C19** | Livro de emissão **comprometido no estado**: conta de sistema `SUPPLY_LEDGER` (`0x4200…0100`, nonce 1, sem código) com **dois slots**: slot 0 = total mintado, slot 1 = **cursor de depósitos** — a posição canônica na L1 `(l1_height, l1_tx_index, l1_vout)` do último escrow consumido (modelo de inbox OP‑Stack/Arbitrum). `DepositProvenance` ganhou `l1_height` e `l1_tx_index`; a camada de derivação deve apresentar os depósitos em ordem estritamente crescente de posição (`validate_block_input` rejeita desordem/duplicata dentro do bloco com `DepositsOutOfOrder`) e a STF só aceita um depósito cuja posição seja estritamente posterior ao cursor (`DepositError::OutOfOrder`), avançando‑o. Isso substitui o conjunto de outpoints consumidos da primeira versão da correção: estado e witness ficam O(1) em vez de O(total de depósitos), e replay/duplicata/desordem tornam‑se estruturalmente impossíveis. `mint_wei` removido de `DepositMint` (crédito derivado de `l1_sats`); teto `ChainSpec::max_l1_sats` por depósito e cumulativo (**placeholder de 21 M BLCH** até o documento de desenho); `ExecutionOutcome::deposits_hash` compromete a lista de depósitos (inclusive posições); fronteira de confiança documentada. | `state::tests::*`, `deposit_outpoint_mints_at_most_once`, `deposits_above_the_l1_cap_are_rejected`; `c10`, `c18`, `c19` |
| **C04 / C08 / C21 / C22 / C23 / C24** | `SparseTrieView::from_proof(prev_state_root, proof)` autentica a raiz (`keccak == prev_state_root`) e **cada nó descido** contra a referência do pai; filhos embutidos (< 32 B) são decodificados no lugar; extensão de chave vazia, caminhos > 64 nibbles, chaves compactas > 33 bytes e RLP inválido são `WitnessError`; `stateless_new_root(prev_state_root, proof, changes) -> Result` recusa mudança dentro de sub‑árvore opaca e remoção de chave ausente. Nenhum `expect`/pânico no caminho do witness. | `stateroot::tests::unanchored_or_injected_proof_nodes_are_rejected`, `changes_inside_opaque_subtrees_…`, `malformed_nodes_are_errors_not_panics`, `inline_children_are_handled`; `c04`, `c08`, `c21`–`c24` |
| **C05 / C06 / C07 / C09 / C12** | Novo `BatchWitness { prev_state_root, new_state_root, proof, pre_accounts, absent_accounts }` (sem `changes`, tudo ordenado). `hydrate_and_verify(&witness)` rejeita duplicatas, contas EIP‑161 vazias, storage zero/desordenado e código inválido, exige que cada conta hidratada seja **folha exposta** com o RLP exato e que cada endereço ausente seja **comprovadamente ausente**. O guest executa sobre `CacheDB<WitnessBacking>`, que **falha** em qualquer leitura fora do witness. `verify_batch` reexecuta, **deriva o conjunto de mudanças** e calcula a raiz; a raiz reivindicada pelo host é comparada, nunca confiada. O host grava o conjunto de leitura completo com um overlay de gravação e só devolve um witness que o próprio `verify_batch` aceita e que reproduz o resultado. | `proving::tests::*` (transferências, contas só lidas, SLOAD de slot vazio, depósitos no guest, witness adulterado); `c05`, `c06`, `c07`, `c09`, `c12` |
| **C14** | Papel de verificador documentado em `execute_block`/`BlockInput::txs` e rejeição tornada não destrutiva (a API de *builder* continua fora do escopo). | — |
| **C20, C29 (parcial), C30** | Efeitos colaterais: witness canônico (vetores ordenados); crédito de zero wei não materializa conta; `cargo test --no-default-features` compila (`#[macro_use] extern crate std` só em testes). | `witness_is_canonical_across_independent_generations`; `c20`, `c29`, `c30` |

**Estado da verificação após as correções:** `cargo test` → 53 testes unitários + 22 regressões ativas aprovados, 10 regressões ignoradas (achados abertos); `cargo test --test audit_regressions -- --ignored` → 10 falhas (C11, C13, C15, C16, C17, C26, C27, C28, C31), como esperado; `cargo test --no-default-features` → 53 aprovados; `cargo clippy --lib` sem avisos.

**Permanecem abertos** (P1/P2 da seção 8): C11 (queima EIP‑6780 não rastreada), C13 (cabeçalho não validado), C15 (legadas pré‑EIP‑155), C16 (`BLOCKHASH`), C17 (EIP‑4788), C26 (views/poda), C27 (custo O(estado) por bloco — **agravado** pela cópia de trabalho da atomicidade, aceito conscientemente até a raiz incremental), C28 (divisão por zero em knobs), C29 (medição de depósitos), C31 (pins exatos/toolchain), além dos itens informativos.

**Decisão tomada a pedido do projeto ("melhor técnica"):** a unicidade de depósitos usa um **cursor monotônico de posição na L1**, não um conjunto de outpoints consumidos — ledger e witness em O(1), replay impossível por construção; o preço é exigir que a derivação apresente os depósitos em ordem canônica (o que ela já faz por construção ao ler a L1 em ordem) e que um depósito pulado pela derivação não possa ser incluído depois (comportamento idêntico ao OP‑Stack). **Ainda exigem confirmação:** o valor de `max_l1_sats` (placeholder de 21 M BLCH) e o endereço do `SUPPLY_LEDGER` (`0x4200…0100`).

---

## 1. Sumário executivo

**Veredito.** O núcleo "honesto" do crate está, em grande parte, correto e foi verificado com rigor: o roteamento de taxas conserva a oferta em Cancun (provado algebricamente contra o handler real do revm 41 e por PoC com reembolsos de SSTORE), a raiz de estado keccak‑MPT é byte‑idêntica à referência de alloy‑trie inclusive com storage real, a fórmula EIP‑1559 coincide com a especificação em 200.000 casos aleatórios, a escala sats⇄wei é exata e a regra de vizinhos do gerador de witness é completa para a trie de contas em 12.240 ensaios randomizados. Nada disso, porém, sustenta as garantias que o crate anuncia, porque:

1. **`execute_block` não é atômico e destrói o estado inteiro do L2 em qualquer erro de transação** (C01, Crítico). O banco é movido para dentro da EVM com `mem::take` e só é devolvido no caminho de sucesso. Uma única tx com nonce errado, saldo insuficiente ou `gas_limit` acima do restante do bloco apaga todos os saldos, nonces e contratos, enquanto o livro de emissão (`total_minted_wei`) continua contando. A raiz de estado passa a ser `EMPTY_ROOT_HASH`; nonces zerados permitem repetir transações já incluídas. Os depósitos são aplicados antes de qualquer validação e nunca são revertidos, de modo que a retentativa natural de um bloco rejeitado **minta duas vezes o mesmo escrow de L1** (C02, Alto).
2. **O caminho de prova stateless é insolúvel frente a um host malicioso, por quatro mecanismos independentes** — o proof nunca é ancorado a `prev_state_root` dentro de `stateless_new_root` (C04, Crítico); contas pré‑existentes podem ser omitidas do witness sem detecção (C05); contas apenas lidas ficam fora do conjunto de acesso e o guest diverge silenciosamente (C06); o conjunto de mudanças `changes` é um dado confiado do host e o fluxo de guest demonstrado pelo crate o usa para calcular a raiz (C09); sub‑árvores opacas são descartadas em silêncio (C08); contas EIP‑161 vazias são hidratadas sem verificação (C12). Além disso, **witnesses honestos são rejeitados** para qualquer chamada de contrato comum que faça SLOAD de um slot vazio (C07): o caminho de prova não tem *liveness* para a forma de transação dominante em qualquer EVM.
3. **As invariantes de oferta ("emissão zero", "nunca queima", "escrow sempre fecha") não são impostas pela STF.** Não há proteção contra replay de depósitos — o mesmo outpoint de L1 pode ser mintado indefinidamente (C10); qualquer `tx_type ≥ 5` (inclusive o 0x7E reservado para depósitos) contorna a validação de taxa do revm e o executor credita ao cofre `basefee × gas` que ninguém pagou — **inflação sem lastro** (C03); `SELFDESTRUCT` para si mesmo na tx de criação **queima** BLCH em Cancun (EIP‑6780) e a invariante `total_native == total_minted` é falsa (C11); `l1_sats` é uma alegação do chamador sem qualquer teto (C19); o livro de emissão não é comprometido na raiz de estado (C18).
4. **Lacunas de paridade de consenso**: ambiente de bloco inteiramente confiado (base fee arbitrária, número/timestamp sem monotonicidade — C13); transações legadas pré‑EIP‑155 aceitas (C15); `BLOCKHASH` devolve um placeholder público e previsível (C16); a chamada de sistema EIP‑4788 está ausente (C17).
5. **Robustez contra witness malformado**: recursão infinita com abort não capturável (C21), comportamento indefinido em release ao ultrapassar 64 nibbles (C22), múltiplos `expect`/asserções alcançáveis por bytes do host (C23), nós inline ignorados (C24).

**Contagem final** (após deduplicação de 89 relatos brutos em 31 achados e verificação adversarial de cada um — nenhum foi refutado; 30 reproduzidos com PoC executada, 1 confirmado parcialmente e rebaixado):

| Severidade | Qtd. | Achados |
|---|---|---|
| **Crítico** | 2 | C01, C04 |
| **Alto** | 9 | C02, C03, C05, C06, C07, C08, C09, C10, C12 |
| **Médio** | 9 | C11, C13, C15, C16, C17, C18, C19, C21, C22 |
| **Baixo** | 11 | C14, C20, C23, C24, C25, C26, C27, C28, C29, C30, C31 |
| **Informativo** | 10 grupos | I01–I10 (documentação, higiene, políticas) + lacunas de testes (§7) |

**Recomendação central.** Não construir o guest SP1 nem o nó sobre `proving.rs`/`stateless_new_root` sem a redefinição descrita em §8‑P0: proof ancorado e verificado nó a nó, conjunto de acesso gravado por um banco de dados rastreador com falha em *miss*, `changes` derivado pelo guest, funções falíveis (`Result`). Tornar `execute_block` atômico e adicionar proteção de replay de depósitos e whitelist de tipos de transação antes de qualquer ancoragem com valor, mesmo em testnet.

---

## 2. Escopo e metodologia

### 2.1 Escopo

Todo o código do repositório: `src/lib.rs`, `src/chainspec.rs`, `src/scale.rs`, `src/state.rs`, `src/executor.rs`, `src/stateroot.rs`, `src/proving.rs`, `src/stubs.rs`, além de `Cargo.toml`, `Cargo.lock`, `.cargo/audit.toml` e `README.md`. As afirmações sobre comportamento de bibliotecas foram verificadas **no código‑fonte vendorizado** das versões exatas do lockfile (revm 41.0.0 e seus sub‑crates `revm-context`, `revm-handler`, `revm-database`, `revm-context-interface`, `revm-interpreter`, `revm-state`, `revm-bytecode`; alloy‑trie 0.9.5; alloy‑rlp 0.3.16; ruint 1.19.0; nybbles 0.4.8), nunca por memória.

**Fora de escopo / limitações:**

* Os documentos de desenho referenciados (`docs/specs/BLOCH-L2-EVM-DESIGN.md`, `BLOCH-L2-PROVER-SCOPE.md`) **não existem neste repositório** (o crate foi replicado de um monorepo); as intenções de desenho foram inferidas dos comentários e do README.
* Não há guest SP1, nó, RPC ou txpool: os achados do caminho de prova referem‑se às **primitivas** que um guest futuro usaria (`hydrate_and_verify`, `execute_block`, `stateless_new_root`), exatamente como os próprios testes do crate modelam o guest (`proving.rs:343-350`).
* `cargo-audit` não está instalado e não havia rede para a base de advisories; a lista de *ignores* em `.cargo/audit.toml` **não** foi revalidada contra a base atual.
* Não foi feita verificação contra `ethereum/tests`/EEST (o crate também não a reivindica).
* A referência independente para a raiz MPT disponível offline (alloy‑trie `root::*`) usa um caminho de RLP distinto, mas o **mesmo** `HashBuilder`; não havia vetor de teste Ethereum com raiz conhecida offline.

### 2.2 Metodologia

1. **Leitura integral em dez lentes independentes**, cada uma por um auditor separado que leu todo o crate e as fontes vendorizadas relevantes: (1) atomicidade e caminhos de erro do executor; (2) roteamento de taxas e conservação de oferta versus o handler real do revm 41; (3) paridade de consenso / configuração da EVM; (4) correção da raiz de estado keccak‑MPT versus a especificação Ethereum e a semântica real do `CacheDB`; (5) solidez do caminho de prova stateless frente a um host/prover malicioso; (6) completude do witness para formas arbitrárias de trie (verificação empírica randomizada); (7) semântica de depósitos/bridge e modelo de oferta; (8) pânicos, DoS e robustez; (9) build, features, cadeia de suprimentos e exatidão da documentação; (10) adequação da suíte de testes.
2. **Provas de conceito executadas.** Cada lente escreveu e rodou crates de teste separados (dependendo de `bloch-l2-evm` por caminho, com o mesmo `Cargo.lock`), sem modificar o repositório. Ao todo foram executados mais de 80 testes de PoC, incluindo 12.240 ensaios randomizados de formas de trie e 200.000 pares aleatórios para a fórmula EIP‑1559.
3. **Deduplicação** dos 89 relatos brutos em 31 achados substantivos e 11 grupos informativos.
4. **Verificação adversarial**: cada achado substantivo foi entregue a um *reprodutor* independente (releitura do código e das fontes vendorizadas, PoC própria, correção de título/severidade/evidência, teste de regressão); os achados de severidade alta/crítica passaram por um painel de *céticos* instruídos a refutar ou rebaixar (um cético quando o fato já tinha duas PoCs independentes de auditores mais a reprodução; três quando não); os de severidade média passaram por um cético; os grupos informativos passaram por verificação factual (números, linhas, saídas de comando). As opiniões divergentes dos céticos sobre severidade estão registradas em cada achado.
5. **Escala de severidade** (para o L2 pretendido): **Crítico** = perda/forja de fundos, forja de raiz de estado ou de prova, divergência de consenso; **Alto** = corrupção de estado, quebra de invariante de oferta ou lacuna de solidez alcançável por entrada realista; **Médio** = comportamento incorreto ou validação ausente com impacto contido; **Baixo** = endurecimento / pânico em entrada malformada; **Informativo** = documentação e higiene.

---

## 3. Tabela de achados

| ID | Sev. | Título curto | Local | Status |
|---|---|---|---|---|
| C01 | Crítico | `execute_block` apaga todo o estado em erro de tx; livro de emissão segue contando | `executor.rs:196, 229-231, 241-246, 279` | Reproduzido → **Corrigido (§0)** |
| C04 | Crítico | `stateless_new_root` não ancora o proof a `prev_state_root`; nós injetados forjam a nova raiz | `stateroot.rs:153-205, 210-247` | Reproduzido → **Corrigido (§0)** |
| C02 | Alto | Depósitos aplicados antes das validações; bloco rejeitado deixa mints e a retentativa minta em dobro | `executor.rs:179-191` | Reproduzido → **Corrigido (§0)** |
| C03 | Alto | `tx_type ≥ 5` contorna validação de taxa; executor credita basefee que ninguém pagou (inflação) | `executor.rs:186-190, 255-263` | Reproduzido → **Corrigido (§0)** |
| C05 | Alto | `hydrate_and_verify` não prova completude; conta pré‑existente omitida → guest diverge e deriva raiz falsa | `proving.rs:175-208` | Reproduzido → **Corrigido (§0)** |
| C06 | Alto | Contas apenas lidas ficam fora do witness; guest diverge com autoverificação do host passando | `proving.rs:141-166` | Reproduzido → **Corrigido (§0)** |
| C07 | Alto | Witness honesto rejeitado quando uma chamada faz SLOAD de slot vazio (liveness da prova) | `proving.rs:87-118, 151` | Reproduzido → **Corrigido (§0)** |
| C08 | Alto | Sub‑árvore opaca descartada em silêncio quando uma mudança cai dentro dela | `stateroot.rs:186-190` | Reproduzido → **Corrigido (§0)** |
| C09 | Alto | Raiz do guest controlada pelo host: `changes` é entrada confiada; sem derivação guest‑side pública | `proving.rs:28-47, 343-350` | Reproduzido → **Corrigido (§0)** |
| C10 | Alto | Sem proteção de replay de depósitos: mesmo outpoint minta repetidamente | `state.rs:117-132` | Reproduzido → **Corrigido (§0)** |
| C12 | Alto | Contas EIP‑161 vazias com storage hidratadas sem verificação; vazam para a raiz pós‑estado | `proving.rs:181-206`, `stateroot.rs:106-109` | Reproduzido → **Corrigido (§0)** |
| C11 | Médio | EIP‑6780 `SELFDESTRUCT` para si queima BLCH; "nunca queima" é falso | `state.rs:7-13, 139-153` | Reproduzido |
| C13 | Médio | Ambiente de bloco confiado ao chamador; base fee nunca validada | `executor.rs:197, 205-219` | Reproduzido |
| C15 | Médio | Transações legadas pré‑EIP‑155 (`chain_id = None`) aceitas | `executor.rs:186-192, 199-204` | Reproduzido |
| C16 | Médio | `BLOCKHASH` devolve placeholder `keccak256(número decimal)` | `executor.rs:196-220` | Reproduzido |
| C17 | Médio | Chamada de sistema EIP‑4788 e predeploy ausentes em Cancun | `executor.rs:178-274` | Reproduzido |
| C18 | Médio | `total_minted_wei` não comprometido na raiz; dessincroniza no guest; forjável | `state.rs:99-105` | Reproduzido → **Corrigido (§0)** |
| C19 | Médio | `l1_sats` é alegação não autenticada; `mint_wei` redundante; sem teto | `state.rs:117-132` | Reproduzido → **Corrigido (§0)** |
| C21 | Médio | Recursão infinita (abort) em extensão de chave vazia no proof | `stateroot.rs:220-227` | Reproduzido → **Corrigido (§0)** |
| C22 | Médio | Ultrapassagem da capacidade de 64 nibbles: pânico em debug, UB em release | `stateroot.rs:217-238` | Reproduzido → **Corrigido (§0)** |
| C14 | Baixo | Semântica "verificador" (tx inválida invalida o bloco) não documentada; sem API de builder | `executor.rs:228-246` | Parcial (rebaixado) |
| C20 | Baixo | Ordem do witness não canônica (HashMap com seed aleatória) | `proving.rs:146-166` | Reproduzido → **Corrigido (§0)** |
| C23 | Baixo | Pânicos em witness malformado (`expect`, asserções de decode/HashBuilder, `Bytecode::new_raw`) | `stateroot.rs:155-247`, `proving.rs:182` | Reproduzido → **Corrigido (§0)** |
| C24 | Baixo | Nós inline (<32 bytes) ignorados: raiz errada em silêncio fora da trie de contas | `stateroot.rs:224-226, 241-243` | Reproduzido → **Corrigido (§0)** |
| C25 | Baixo | Preço efetivo recalculado sem `tx_type`; `priority_fee_routed_wei` subnotifica | `executor.rs:232-239, 266` | Reproduzido → **Corrigido (§0)** |
| C26 | Baixo | Views reportam contas vazias como existentes; contas fantasma e slots zero nunca podados | `state.rs:143-198` | Reproduzido |
| C27 | Baixo | Raiz recomputada do zero a cada bloco; witness clona o estado e reconstrói a trie ~5× | `stateroot.rs:85-115`, `proving.rs:75-166` | Reproduzido |
| C28 | Baixo | Divisão por zero em `gas_target`/`next_base_fee` com knobs públicos zerados | `chainspec.rs:85-113` | Reproduzido |
| C29 | Baixo | Depósitos gratuitos e ilimitados; depósito de 0 sats cria conta permanente | `executor.rs:178-184`, `state.rs:185-198` | Reproduzido → **Parcialmente corrigido (§0)** |
| C30 | Baixo | `cargo test --no-default-features` não compila; no_std nominal nas dependências | `lib.rs:54-61`, `Cargo.toml:28-50` | Reproduzido → **Corrigido (§0)** |
| C31 | Baixo | Determinismo só pelo `Cargo.lock`: ranges caret, sem pin de toolchain, backends C/asm | `Cargo.toml:28-39` | Reproduzido |

---

## 4. Achados detalhados

Convenções: **Status** indica *Reproduzido* (PoC independente executada), *Confirmado por análise* ou *Parcial*. **Painel** registra a opinião de severidade dos céticos quando divergiu da adotada. **Documentado** indica que o crate já menciona a limitação em algum comentário.

### 4.1 Críticos

#### C01 — `execute_block` apaga todo o estado do L2 em `BlockGasLimitExceeded` ou em qualquer erro do revm, enquanto `total_minted_wei` continua contando

**Severidade:** Crítico. **Painel:** o cético classificou como Alto, argumentando que não há forja de valor e que as raízes pós‑apagamento são determinísticas; mantido Crítico porque a raiz de estado resultante (`EMPTY_ROOT_HASH`, e depois raízes não vazias porém erradas) seria ancorada por um nó que continue operando, o gatilho é qualquer transação inválida de um usuário sem privilégio, e o efeito é a perda de todos os saldos registrados. **Status:** Reproduzido (6 relatos independentes + reprodução). **Documentado:** parcialmente — `executor.rs:112-114` diz "o estado pode estar parcialmente avançado; este scaffold não implementa rollback", o que subestima materialmente o comportamento (o estado não fica *parcialmente avançado*; é apagado).

**Local:** `src/executor.rs:196` (`let db = core::mem::take(&mut state.db);`), `:229-231` (retorno em `BlockGasLimitExceeded`), `:241-246` (`?` em `transact_commit`), `:279` (única restauração, só no sucesso), `:181-183` (depósitos aplicados antes do *take*).

**Descrição.** O banco `CacheDB` inteiro é movido para dentro do contexto da EVM e só é escrito de volta em `state.db` no caminho de sucesso. Dois retornos antecipados ficam entre esses pontos, dentro do laço de transações: o limite de gás do bloco e o `?` sobre `evm.transact_commit(tx)`, que dispara para **todo** erro de pré‑validação do revm (`NonceTooHigh`/`NonceTooLow`, `LackOfFundForMaxFee`, `InvalidChainId`, `GasPriceLessThanBasefee`, `PriorityFeeGreaterThanMaxFee`, `CallGasCostMoreThanGasLimit`, tipo não suportado…). Em ambos, `evm` — e a única cópia do banco — é descartada. `L2State` deriva `Default`, logo `state.db` fica um `InMemoryDB` vazio. O revm **não** tem culpa: `catch_error` chama `journal.discard_tx()` e nunca faz commit da tx falha (`revm-handler/src/handler.rs:557-567`; `api.rs:143-147`), de modo que o banco dentro da EVM permanece consistente — o crate simplesmente o joga fora.

**Consequências (todas reproduzidas):** (a) toda conta, saldo, nonce, contrato e slot desaparecem, inclusive contas que o bloco não tocou e transações do mesmo bloco já confirmadas por `transact_commit`; (b) `total_minted_wei` permanece e inclui os depósitos do bloco falho, logo `total_native_wei() == 0 != total_minted_wei()` — a invariante central do crate é quebrada permanentemente; (c) `compute_keccak_mpt_state_root` devolve `EMPTY_ROOT_HASH` e todo bloco seguinte devolve uma raiz não vazia, confiante e errada; (d) nonces voltam a zero, de modo que a exata transação de nonce 0 já incluída em um bloco anterior é aceita novamente quando a conta é refinanciada. Os erros anteriores ao *take* (`Deposit`, `BlobTxRejected`) não apagam o banco, mas deixam os depósitos do bloco falho aplicados (ver C02).

**PoC (trecho).** Pré‑estado com 5 contas, ALICE nonce 1, `native == minted == 15 BLCH`. Bloco 3 = [depósito 1 BLCH → BOB, tx válida nonce 1, tx nonce 7] → `Err(Evm{tx_index:1, NonceTooHigh})`; depois: `accounts_in_db=0 alice=0 (nonce 0) carol=0 total_native_wei=0 total_minted_wei=16 BLCH root=0x56e81f17…b421 (EMPTY_ROOT_HASH)`. O mesmo com `BlockGasLimitExceeded{tx_index:0}`, `LackOfFundForMaxFee`, `InvalidChainId`, `GasPriceLessThanBasefee`. Bloco 4 após o apagamento aceita de novo a transferência de nonce 0 do bloco 2.

**Recomendação.** Tornar a aplicação do bloco atômica: executar sobre uma cópia/camada bufferizada (incluindo o passo de depósitos) e só no sucesso completo atribuir `state.db` e somar `total_minted_wei`; em qualquer `Err` devolver sem tocar em `state`, deixando‑o byte‑idêntico ao pré‑bloco. Patch mínimo se clonar for inaceitável: mover os passos 3‑5 para uma função interna e **sempre** escrever `state.db = evm.ctx.journaled_state.database` antes de propagar o erro, revertendo também depósitos/`total_minted_wei`. Adicionar testes para cada variante de erro (índice 0 e >0) afirmando estado, saldos, nonces, `total_native_wei == total_minted_wei` e raiz idênticos ao pré‑bloco. Corrigir a documentação de `BlockExecutionError`.

#### C04 — A raiz pós‑estado stateless é calculada a partir de um proof não autenticado: `stateless_new_root` não recebe `prev_state_root` e `collect_sparse` nunca encadeia hashes dos nós descidos

**Severidade:** Crítico (reprodutor e cético concordam). **Status:** Reproduzido (3 relatos + reprodução). **Documentado:** não.

**Local:** `src/stateroot.rs:153-205` (`stateless_new_root(proof, changes) -> B256`, sem parâmetro de raiz), `:210-247` (`collect_sparse`: descida em extensão `:220-227` e em ramo `:239-243` sem `keccak(nó) == child.as_hash()`; raiz nunca comparada a `prev_state_root` em `:161-162`), `src/proving.rs:194-206` (`hydrate_and_verify` liga só os caminhos das folhas de `pre_accounts`).

**Descrição.** O walker desce por estrutura, não por criptografia: para um filho de ramo/extensão cujo caminho está **presente** no mapa do proof, recorre para o que quer que o host tenha fornecido; a referência de hash do pai só é consultada no `else if` para filhos **ausentes** (fronteira opaca). Valores de folhas expostas mas não alteradas são lidos diretamente dos bytes do proof e emitidos tais quais no `HashBuilder` da nova raiz. A única âncora do lado do guest, `hydrate_and_verify`, executa `verify_proof` apenas ao longo dos caminhos das contas em `pre_accounts` — e `verify_proof` de alloy‑trie (`src/proof/verify.rs:47-59`) segue um único caminho de chave; nós fora de todo caminho hidratado jamais são checados. Como `pre_accounts` contém só contas que pré‑existiam **e** mudaram, destinatários e cofres criados no bloco nunca estão nela; um lote que apenas minta para endereços novos hidrata **zero** folhas, e nesse caso `hydrate_and_verify` não liga nada a `prev_state_root` — até um `prev_state_root` errado é aceito.

**Ataques reproduzidos (todos com `hydrate_and_verify` = Ok):** (a) injeção de folha fabricada em um caminho de fronteira opaca (saldo 2^200) → raiz forjada `0xd0c77b45…`; (b) reescrita dos bytes de uma folha vizinha exposta → `0xa44585ae…`; (c) proof vazio → `0x60aba89d…` (raiz honesta: `0x206f18ef…`); (d) `hydrate_and_verify(&[], proof vazio, prev_root=0x7777…) = Ok`. Um guest SP1 montado como `hydrate_and_verify + execute_block + stateless_new_root` (o padrão dos próprios testes do crate) comprometeria o par (`prev_state_root` real, `new_state_root` forjado): forja arbitrária de pós‑estado.

**Recomendação.** (1) Dar a `stateless_new_root` um parâmetro `prev_state_root` e retorno `Result`. (2) Na raiz, exigir `keccak256(proof[[]]) == prev_state_root` (ou `proof[[]] == [0x80]` sse `prev_state_root == EMPTY_ROOT_HASH`); rejeitar raiz ausente com `changes` não vazio. (3) Em `collect_sparse`, antes de recorrer em um filho exposto em `cp`, verificar `keccak256(proof[cp]) == child.as_hash()` e rejeitar filhos inline explicitamente. (4) Não depender de `hydrate_and_verify` para integridade do proof; ligar toda folha que o guest **consome** (vizinhos expostos, chaves removidas) e fazer `pre_accounts` vazio falhar a menos que `prev_state_root == EMPTY_ROOT_HASH`. Alternativa: adotar `reth-trie-sparse`, que constrói a trie esparsa a partir de um proof já verificado contra a raiz. Adicionar testes negativos com witness adversarial.

### 4.2 Altos

#### C02 — Depósitos são aplicados antes de qualquer validação de bloco e sem rollback; um bloco rejeitado deixa os depósitos creditados/contados e a nova proposta dos mesmos depósitos ancorados minta em dobro

**Severidade:** Alto (cético concorda). **Status:** Reproduzido. **Documentado:** parcialmente (`executor.rs:112-114`).

**Local:** `src/executor.rs:181-184` (laço de depósitos), `:187-191` (checagem de blob depois dos depósitos), `:196` (`mem::take`), `:229-231`, `:241-246`; `src/state.rs:117-132`.

**Descrição.** O passo 1 credita `state.db` e incrementa `total_minted_wei` para cada depósito **antes** da rejeição de blob, do limite de gás e da validação do revm. Nenhum caminho de erro desfaz os depósitos, e o `ExecutionOutcome` com `minted_wei` não é devolvido em `Err`, logo o chamador nem sabe quanto foi mintado. Três consequências reproduzidas: (1) `BlobTxRejected` dispara depois dos depósitos e antes do *take*: a função devolve `Err`, mas `state.db`, `total_minted_wei` e a raiz já avançaram; como `BlockInput` documenta que depósitos "não podem ser descartados uma vez ancorados" (`executor.rs:55-57`), a reação natural do sequenciador é remover a tx ofensora e repropor o bloco com os mesmos `DepositMint`s — a retentativa **minta o mesmo escrow de L1 outra vez** (PoC: BOB = 6 BLCH para 3 BLCH escrowados; `total_native == total_minted` continua valendo, o livro é cego à inflação; não há proteção por outpoint em lugar algum — ver C10); (2) `DepositError` no depósito *k* deixa os depósitos 0..k‑1 aplicados; (3) `BlockGasLimitExceeded`/`Evm` descartam o banco mas `total_minted_wei` mantém os depósitos (livro diverge).

**Recomendação.** Validação pura antes de tocar em `state` (blob/tipo, `gas_limit` por tx e cumulativo, exatidão de cada depósito), aplicação em cópia de trabalho com escrita de volta só em `Ok`; independentemente, proteção de replay por `(l1_txid, l1_vout)` (C10). Estender `blob_transactions_are_rejected_at_the_sequencer` e `block_gas_limit_exceeded_is_rejected` para afirmar saldos e livro intactos após `Err`.

#### C03 — A fronteira do sequenciador só bloqueia `tx_type == 3`: qualquer `tx_type ≥ 5` (inclusive o 0x7E reservado a depósitos) chega ao revm como `TransactionType::Custom`, pula as verificações de taxa e chain‑id específicas de tipo, e o executor credita ao `BaseFeeVault` um `basefee × gas` que ninguém pagou

**Severidade:** Alto (cético concorda). **Status:** Reproduzido. **Documentado:** não — ao contrário, `lib.rs:33-34` e `executor.rs:16-17` afirmam rejeitar tipos inválidos "exatamente como nos L2s OP‑Stack".

**Local:** `src/executor.rs:186-190` (só tipo 3), `:255-263` (crédito incondicional de `base_fee × gas_used`); `revm-context-interface/src/transaction/transaction_type.rs:52-62` (`_ => Custom`), `revm-handler/src/validation.rs:139-147, 209-211` ("Custom transaction type check is not done here"), `revm-context-interface/src/transaction.rs:147-160`, `revm-handler/src/post_execution.rs:119-130`.

**Descrição.** Para um `TxEnv` com `tx_type ≥ 5` e `gas_price = 0`, o revm 41 não aplica `GasPriceLessThanBasefee` nem exige `chain_id` (`!is_legacy && !is_custom`), cobra do chamador `effective_gas_price × gas_limit = 0` e paga `saturating_sub(basefee) = 0` ao coinbase; o executor, porém, assume que o basefee foi cobrado e credita `base_fee × gas_used` ao cofre. É wei criado do nada: `total_native_wei() > total_minted_wei()`. Uma conta que nunca existiu pode submeter tais transações (nonce 0, 1, 2…) e consumir gás do bloco de graça, inflando o cofre a cada uma; o montante é limitado só por `gas_limit × base_fee` por bloco. Correção do cético incorporada: a inflação ocorre quando o preço efetivo fica **abaixo** do basefee — o valor sem lastro é `(basefee − effective) × gas_used`; um tipo customizado que pague ≥ basefee contabiliza corretamente. A realidade do vetor é dada pelo próprio desenho (`state.rs:30`: depósitos como "envelope OP‑style tipo 0x7E"), e no Ethereum Cancun um byte de tipo desconhecido é inválido por consenso — o mesmo bloco é inválido em um cliente de referência e válido aqui.

**PoC.** `[tx_type=0x7e gas_price=0] success=true gas_used=21000 supply_delta=21000000000000`; idem para 0x05 e 0x10; contraste: tipos 0/1/2 com `gas_price=0` → `GasPriceLessThanBasefee`, tipo 4 → `Eip7702NotSupported`, tipo 3 → rejeitado pelo executor.

**Recomendação.** Substituir a blacklist por whitelist `{0,1,2}` em Cancun com `BlockExecutionError::UnsupportedTxType { tx_index, tx_type }`, mantendo a checagem antes do `mem::take`. Independentemente, derivar o roteamento do que o revm **realmente** cobrou (usar `tx.effective_gas_price(base_fee)` do próprio revm e rotear `min(effective, base_fee) × gas_used`, ou melhor, uma checagem de conservação por transação que aborte o bloco em caso de divergência).

#### C05 — `hydrate_and_verify` prova apenas a inclusão das `pre_accounts` escolhidas pelo host, nunca a completude: uma conta pré‑existente tocada pode ser omitida, o guest reexecuta contra uma conta falsamente vazia e o multiproof honesto produz uma raiz pós‑estado derivável e errada

**Severidade:** Alto. **Painel:** o cético classificou como **Crítico** ("o impacto é maior que o descrito"), pois, combinado com a derivação guest‑side de `changes`, resulta em raiz forjada derivável de um proof honesto. Mantido Alto como achado individual; a combinação C04+C05+C09 é tratada como crítica no sumário. **Status:** Reproduzido. **Documentado:** não.

**Local:** `src/proving.rs:175-208` (laço de inclusão `:193-206`, único uso de `verify_proof`, sempre com `Some(value)`); `alloy-trie/src/proof/verify.rs:14-23` (forma de exclusão `None`, nunca usada); `src/stateroot.rs:169-172`.

**Descrição.** A rotina hidrata um `L2State` novo com o que o host colocou em `pre_accounts` e verifica **as folhas desse estado hidratado**. Nada enumera os endereços que o lote realmente toca, nada chama `verify_proof(.., None, ..)` (prova de exclusão), e não há noção de conjunto de acesso obrigatório. Um endereço ausente lê como EIP‑161 vazio no `CacheDB<EmptyDB>`. PoC (30 contas, transferência de 1 BLCH de `addr(3)` para `addr(7)` que já tinha 5 BLCH): removendo só a entrada do destinatário, `hydrate_and_verify` = Ok, o guest vê saldo prévio 0 e pós 1e18 (honesto: 6e18); derivando `changes` do próprio par pré/pós e alimentando `stateless_new_root(&proof_honesto, &changes_guest)`, a chave do destinatário já está exposta no multiproof, o "insert" do guest é aplicado como *update* (`stateroot.rs:169-172`) e a raiz resultante `0x1f5ffde5…` é exatamente a raiz do estado real com o saldo do destinatário sobrescrito para 1 BLCH (5 BLCH destruídos). Omitir o remetente causa `LackOfFundForMaxFee` (DoS); omitir um contrato transforma a CALL em transferência simples. Sub‑lacunas: endereços duplicados em `pre_accounts` não são rejeitados (a última `info` vence, o storage é a **união**); contas EIP‑161 vazias são invisíveis ao laço de verificação (ver C12).

**Recomendação.** Tornar a completude uma propriedade verificada: banco rastreador no guest que registre todo endereço/slot carregado e falhe em *miss*; para cada endereço tocado exigir inclusão **ou** prova de exclusão contra `prev_state_root`; rejeitar duplicatas e contas vazias com storage; no host, gravar o conjunto de leitura (não só o de mudança) e estender a autoverificação para hidratar e reexecutar a partir de `pre_accounts`.

#### C06 — O conjunto de acesso do witness omite toda conta apenas lida (tocada mas inalterada) e o guest não tem provas de exclusão: `generate_batch_witness` retorna Ok, `hydrate_and_verify` passa e a reexecução do guest diverge silenciosamente da raiz do host

**Severidade:** Alto (cético concorda). **Status:** Reproduzido. **Documentado:** sim, parcialmente — a NOTA em `proving.rs:142-145` reconhece que contas de leitura pura "não são cobertas" e afirma que transferências, mints e roteamento de taxas só tocam contas que também alteram (verdadeiro, mas qualquer chamada de contrato quebra a premissa).

**Local:** `src/proving.rs:147-154` (predicado `pre_acc.info != post_acc.info || pre_acc.storage != post_acc.storage`), `:135-139` (autoverificação que não reexecuta), `:180, 194-206`; `revm-interpreter/src/instructions/host.rs:39-45` (`BALANCE` carrega sem tocar), `revm-database/src/in_memory_db.rs:145-177`.

**Descrição.** Alvos de `BALANCE`/`EXTCODESIZE`/`EXTCODEHASH`/`EXTCODECOPY`, alvos de `STATICCALL`/`CALL`/`DELEGATECALL` cujo código roda sem alterar o próprio estado (funções *view*, routers, bibliotecas) e leituras de slots já em cache nunca diferem no `CacheDB`, logo são excluídos. A autoverificação do host só rehasheia o **próprio** conjunto de mudanças contra a **própria** raiz. PoC: contrato C armazena `BALANCE(D)` no slot 0 (D é EOA financiado e inalterado): D ausente de `pre_accounts`; host `slot0(C)=7e18`, guest `0`; raiz derivada pelo guest `0x493c8c5f…` ≠ `0x8952ec90…`. Variante A2: gás e sucesso **idênticos** (28.612) com raízes divergentes — invisível à comparação de recibo que o único teste de guest do crate faz (`proving.rs:347-348`). Anexar D a `pre_accounts` faz o guest coincidir bit a bit: a única peça faltante é a completude do conjunto de acesso.

**Recomendação.** Gravar o conjunto de acesso completo durante a execução do host (camada `Database` que registra `basic`, `code_by_hash`, `storage`), incluindo contas lidas e ausentes (para provas de não inclusão); no guest, hidratação completa e verificável com erro duro em *miss*; autoverificação fiel ao guest (hidratar, reexecutar, derivar `changes`, comparar raiz e recibos).

#### C07 — Witnesses honestos são rejeitados por `hydrate_and_verify` para qualquer chamada de valor zero que faça SLOAD de um slot vazio ou SSTORE 0→0: `pre_accounts` é selecionado pelo diff bruto do `CacheDB` e os alvos do proof pelo diff de folhas da trie

**Severidade:** Alto. **Painel:** dividido — dois céticos classificaram como Médio (é falha de *liveness*, não de solidez; o gatilho preciso é a primeira carga de um slot zero ainda não presente no cache do host) e um como Alto. Mantido Alto porque torna o caminho de prova inutilizável para a forma dominante de transação e a garantia "correct‑or‑error" do módulo é falsa. **Status:** Reproduzido. **Documentado:** não.

**Local:** `src/proving.rs:87-100` (alvos = diff de folhas), `:108-118`, `:151` (predicado bruto), `:135-139`, `:193-206`; `revm-database/src/in_memory_db.rs:171-175` (commit estende o storage com cada slot carregado, inclusive zero), `revm-context/src/journal/inner.rs:432-449` (CALL de valor zero toca o destinatário).

**Descrição.** Um contrato chamado que lê um slot vazio (ou escreve 0 num slot vazio) termina com storage em cache `{slot: 0}` onde o pré‑estado tinha `{}`: o mapa difere, mas a folha da trie é byte‑idêntica (slots zero são filtrados de `storage_root`). O contrato é emitido em `pre_accounts` mas **não** é alvo do proof, logo o multiproof não contém nós do seu caminho (salvo se por acaso for vizinho de uma chave alterada) e `verify_proof` falha com `ValueMismatch { got: None }`. A autoverificação do host passa. Correções dos céticos incorporadas: só a metade `storage` do predicado dispara (`AccountInfo::eq` compara apenas saldo/nonce/code_hash); não vale para `STATICCALL`/`DELEGATECALL` nem para chamadas revertidas (o *touch* é desfeito); após uma primeira carga, releituras do mesmo slot em lotes seguintes não disparam — caem na lacuna complementar de omissão (C06).

**PoC.** 60 EOAs + contrato `PUSH1 0 SLOAD STOP`, chamada de valor zero: `generate_batch_witness = Ok`; `hydrate_and_verify => Err(pre-account does not open against prev_state_root: value mismatch … got: None)`. Com 6 contas passa (vizinho); com 1 wei de valor passa (folha muda).

**Recomendação.** Um único predicado canônico de "tocado" (comparar folhas ou `AccountInfo` + storage filtrado de zeros); todo endereço emitido em `pre_accounts` deve ser alvo do `ProofRetainer`; conjunto de leitura via banco rastreador; autoverificação ponta a ponta.

#### C08 — `stateless_new_root` descarta em silêncio uma sub‑árvore de fronteira opaca inteira quando uma chave de mudança desce para dentro dela (e ignora remoções de chaves não expostas): raiz errada, sem erro, mesmo com proof ancorado e pré‑estado verificado

**Severidade:** Alto (três céticos concordam). **Status:** Reproduzido. **Documentado:** sim — `stateroot.rs:148-152` reconhece a divergência e delega a prevenção ao gerador de witness do host.

**Local:** `src/stateroot.rs:186-190` (fronteira omitida se `changes.keys().any(|ck| ck.starts_with(path))`), `:171` (`Some(None) => {}` só para folhas expostas), `:177-183`; retorno `B256` sem canal de erro.

**Descrição.** Forma adversarial reproduzida: mantendo `changes` honesto (derivado pelo guest) e deixando o prover escolher só a **forma** do proof, remover os nós sob a sub‑árvore filha da raiz onde a conta **recém‑inserida** (bob) cai deixa um proof cuja raiz ainda hasheia para `prev_state_root` e para o qual `hydrate_and_verify` passa (as contas hidratadas vivem em outros ramos). `stateless_new_root(stripped, changes_honesto)` devolve `0x00b576d9…` em vez de `0xedd4c486…`, valor igual à raiz do pós‑estado com as 3 contas intocadas da sub‑árvore de bob **removidas**. A falta de ancoragem (C04) **não** é necessária para esse ataque. Fato reforçador verificado pelos céticos: `verify_proof` de alloy‑trie aceita o proof truncado como prova de **não inclusão** válida da chave de bob (retorna `Ok` quando o caminho termina em filho só‑hash), portanto adicionar prova de exclusão por conta criada não detectaria o ataque — a correção precisa estar dentro de `stateless_new_root`.

**Recomendação.** Tornar a função *correct‑or‑error*: `Result<B256, _>`, erro quando qualquer chave de mudança tem um caminho de fronteira opaca como prefixo (o teste já existe em `:187` como *skip* silencioso) e quando uma chave de mudança não é folha exposta nem comprovadamente ausente; verificar a raiz do proof contra `prev_state_root`; propagar o erro em `generate_batch_witness`.

#### C09 — A raiz pós‑estado do guest é controlada pelo host: `BatchWitness.changes` é entrada confiada, o crate não oferece derivação guest‑side do conjunto de mudanças (`account_leaves` é `pub(crate)`) e o fluxo de guest demonstrado compromete `stateless_new_root(proof, witness.changes)`

**Severidade:** Alto (três céticos concordam). **Status:** Reproduzido. **Documentado:** não.

**Local:** `src/proving.rs:28-47` (`changes` como campo do witness), `:83-100` (calculado no host), `:135-139`, `:175-208` (`hydrate_and_verify` nunca inspeciona `changes`), `:280-284` e `:343-350` (testes de guest que reexecutam e depois comprometem o `changes` do **host**); `src/stateroot.rs:94` (`account_leaves` privado ao crate), `:35`, `:64`.

**Descrição.** Com proof e `pre_accounts` honestos, um host que apenas reescreva `changes[keccak(alice)]` para uma folha RLP com saldo 10^30 wei passa `hydrate_and_verify`, reexecuta para o saldo honesto de Alice (3,999958e18) e o fluxo de guest demonstrado atesta a raiz `0x96138dc6…`, exatamente a raiz do pós‑estado honesto com o saldo de Alice substituído por 10^30 wei. A reexecução nunca entra na raiz comprometida. Correção dos céticos incorporada: "um guest sólido não é exprimível" é exagero — como `L2State.db` é público, um crate externo pode reimplementar a codificação de folhas e o diff (e `generate_batch_witness` chamado sobre o pré‑estado parcial hidratado devolve `changes` idêntico ao honesto); o defeito é o desenho de witness com entrada confiada, a ausência de derivação pública e o padrão inseguro demonstrado.

**Recomendação.** API pública `verify_batch(witness, spec, input) -> Result<B256>` que hidrata/verifica, reexecuta, deriva as mudanças por diff das folhas provadas contra as folhas reexecutadas e devolve a raiz stateless sem ler `changes` do host; remover `changes` do witness (ou tratá‑lo como dica a ser recomputada e comparada); reescrever os dois testes de `proving.rs` e adicionar teste negativo; combinar com C04 e C06.

#### C10 — Sem proteção de replay de depósitos: o mesmo outpoint de escrow de L1 `(l1_txid, l1_vout)` minta repetidamente dentro de um bloco, entre blocos e através do caminho de prova; outpoints consumidos não são comprometidos no estado

**Severidade:** Alto (cético concorda). **Status:** Reproduzido. **Documentado:** não — o teste `deposit_mints_exactly_and_supply_equals_sum_of_mints` (`state.rs:220-239`) aplica a mesma proveniência `([0x42;32], 0)` três vezes e afirma sucesso, codificando o replay.

**Local:** `src/state.rs:118` (`let DepositProvenance::BridgedBlch { l1_sats, .. }` — outpoint descartado), `:99-105` (sem conjunto de consumidos); `src/executor.rs:181-184`, `:35-48` (sem referência a L1); `src/proving.rs:180`; `src/stateroot.rs:85`.

**Descrição e PoC.** (a) o mesmo `DepositMint` duas vezes num bloco → `minted_wei = 2 BLCH` para um escrow de 1 BLCH; (b) mesmo outpoint em 5 blocos → 5 BLCH, com `total_minted == total_native` (o livro registra os mints sem lastro como oferta legítima); (c) dois depósitos com o mesmo outpoint e `l1_sats`/destinatários contraditórios são ambos aceitos; (d) `generate_batch_witness` sobre um bloco de replay autoverifica e o guest reproduz `new_state_root` — uma prova de validade sobre esta STF **atesta mints sem lastro**. Gatilhos realistas: bug de derivação que encaminha um depósito duas vezes, rederivação após reorg do Bloch (antecipada pelo próprio desenho), sequenciador malicioso.

**Recomendação.** Conjunto de outpoints consumidos (ou cursor monotônico de depósitos/L1‑origin em `BlockContext`) em `L2State`, com `DepositError::Replay` e no‑op; rejeitar duplicatas no próprio `BlockInput` antes de mintar; **comprometer** o conjunto/cursor (e idealmente `total_minted_wei`) na keccak‑MPT como slots de um predeploy de sistema, para que `hydrate_and_verify`/`stateless_new_root` permitam ao guest impor a regra; corrigir o helper de teste e adicionar testes de rejeição.

#### C12 — `hydrate_and_verify` nunca liga contas EIP‑161 vazias a `prev_state_root`: storage plantado pelo host sob um endereço sem código é hidratado sem verificação e vaza para a folha/raiz pós‑estado do guest após uma transferência simples

**Severidade:** Alto (elevado de Médio pelo reprodutor; cético concorda). **Status:** Reproduzido. **Documentado:** não — `proving.rs:42-46, 171-174` afirmam que **cada** `WitnessAccount` é ligado a `prev_state_root`.

**Local:** `src/proving.rs:181-191` (inserção incondicional), `:194-206` (só as folhas de `account_leaves` são verificadas); `src/stateroot.rs:106-108` (filtro EIP‑161 antes de olhar o storage em `:109`); `revm-database/src/in_memory_db.rs:160-176` (commit só limpa storage de contas **criadas**).

**Descrição.** Qualquer `WitnessAccount` com nonce 0, saldo 0 e código vazio — com qualquer storage — não gera folha, nunca é checado contra o multiproof e permanece no estado do guest como conta existente com storage escolhido pelo host. Consequências: `pre_accounts = []` retorna Ok para qualquer proof/raiz (até proof lixo contra `0x42…42`); escalada reproduzida no cenário de transferência do próprio crate (Alice → Bob novo): anexar `WitnessAccount{bob, 0, 0, [], storage: [(1, 0xdead)]}` é aceito, a execução é idêntica (21.000 gás), mas a folha pós de Bob passa a ter `storage_root({1: 0xdead})` em vez de `EMPTY_ROOT_HASH`, e um guest que derive `changes` do próprio pré/pós produz `0x9f1e…b138` em vez da raiz canônica `0xd9eb…60ab`. Correção do cético: tal conta não pode existir **neste** L2 (gênese vazia + revm Cancun), embora exista no mainnet pré‑Spurious‑Dragon (EIP‑7610); o revm 41 não implementa EIP‑7610 (colisão de CREATE só olha `code_hash`/`nonce`).

**Recomendação.** Verificar **toda** entrada: rejeitar contas EIP‑161 vazias (ou exigir prova de exclusão e não inserir nada), rejeitar vazias com storage/código e slots de valor zero, rejeitar endereços duplicados, e checar independentemente que o nó raiz do proof hasheia para `prev_state_root` (ou tornar o caso vazio um `Ok` documentado só quando o proof também é vazio).

### 4.3 Médios

#### C11 — `SELFDESTRUCT` para si mesmo na transação de criação (EIP‑6780) queima BLCH bridgeado: a invariante documentada "nunca queima / oferta nativa total == total mintado / escrow sempre fecha" é falsa sob revm Cancun não modificado e não é testada

**Severidade:** Médio (cético concorda). **Status:** Reproduzido. **Documentado:** não — a afirmação contrária aparece em `lib.rs:29-34, 49`, `chainspec.rs:16-19, 53`, `state.rs:7-13, 139-142`, `executor.rs:12-15, 100, 253`, `README.md:22-23, 55-56`.

**Descrição.** Comportamento consensualmente **correto** de Ethereum: um contrato criado na mesma transação que executa `SELFDESTRUCT` com o próprio endereço como beneficiário tem o saldo zerado sem crédito a ninguém (`revm-context/src/journal/inner.rs:640` pula o crédito quando `address == target`; `:664-674` zera o saldo; o log EIP‑7708 só existe a partir de Amsterdam, logo em Cancun **nenhum** rastro é emitido). Initcode de 2 bytes `0x30ff` (`ADDRESS SELFDESTRUCT`) com valor num CREATE basta: tx bem‑sucedida (58.036 gás), taxas roteadas corretamente, `total_minted_wei − total_native_wei == valor`. A direção é segura para a solvência (escrow sobrecolateralizado), mas qualquer componente de bridge/reconciliação que trate a igualdade como checagem dura falha após a primeira dessas transações.

**Recomendação.** Corrigir a afirmação, não o revm: "o **protocolo** nunca queima; a EVM pode destruir valor via EIP‑6780" e `total_native == total_minted − total_burned`; rastrear `total_burned_wei` (diff da soma de saldos antes/depois de cada `transact_commit`, ou pelas entradas de selfdestruct do journal) e expô‑lo em `ExecutionOutcome`; alternativa (delta de consenso documentado) redirecionar o valor ao `BASE_FEE_VAULT`. Adicionar testes para os três casos (self na criação, outro alvo na criação, self em contrato pré‑existente).

#### C13 — O ambiente de bloco (base fee, número, timestamp, prevrandao) é confiado ao chamador: `execute_block` nunca impõe `ChainSpec::next_base_fee` nem monotonicidade em relação ao cabeçalho pai

**Severidade:** Médio (cético concorda). **Status:** Reproduzido. **Documentado:** parcialmente — `BlockContext` é descrito como "escolhido pelo sequenciador" e só `timestamp` como "não verificado"; que a regra `next_base_fee` (apontada pelo próprio doc de `base_fee_per_gas`) não é aplicada, não está documentado.

**Local:** `src/executor.rs:197, 205-219, 232-268`; `src/chainspec.rs:93-113` (`next_base_fee` sem nenhum call site fora dos próprios testes); `BlockExecutionError` sem variante de cabeçalho; `BatchWitness` sem cabeçalho.

**Descrição e PoC.** Base fee 5 gwei onde a regra exige 0,996 gwei: aceito, todo o `max_fee` do usuário vai ao `BaseFeeVault` (tip espremido a 0); base fee 0: aceito, transações com `gas_price = 0` executam de graça e 100% do preço efetivo vai ao cofre do operador — a divisão entre cofres é escolha por bloco do operador, não garantia de protocolo; bloco 7 seguido de bloco 1 e de outro bloco 1, timestamp 99999 seguido de 3: aceitos, contratos observam esses valores; o caminho de witness gera provas válidas para o mesmo lote sob três base fees distintas com três raízes diferentes, sem nenhum campo de cabeçalho no witness. O teste `zero_basefee_routes_nothing_to_the_base_fee_vault` abençoa base fee 0.

**Recomendação.** Carregar o cabeçalho pai em `L2State`/`BlockInput` e, antes de qualquer mutação, exigir `number == parent + 1`, `timestamp >= parent.timestamp` (+ drift do anchor), `base_fee == spec.next_base_fee(parent.base_fee, parent.gas_used)`, com novas variantes de erro; incluir o cabeçalho nas entradas públicas do guest; derivar `prevrandao` como o desenho especifica.

#### C15 — Transações legadas não protegidas (pré‑EIP‑155, `chain_id = None`) são aceitas por `execute_block`: a STF não fornece proteção contra replay entre cadeias para o tipo 0

**Severidade:** Médio (cético concorda). **Status:** Reproduzido. **Documentado:** não — o doc de `BlockExecutionError::Evm` (`executor.rs:130-131`) menciona só o caso `Some(outro)`.

**Descrição.** O revm 41 implementa a regra do L1 (`validation.rs:139-147`): `Some(x ≠ chain_id)` → `InvalidChainId`; tipos 1/2 com `None` → `MissingChainId`; **legada com `None` é aceita**. PoC: o mesmo `TxEnv` legado sem chain id executa com sucesso sob `chain_id` 700771, 1, 10 e 8453. Uma transação não protegida já transmitida por um usuário em outra cadeia EVM (padrão comum em fábricas de implantação determinística) pode ser reproduzida no Bloch L2 contra o saldo desse remetente se o nonce coincidir. Como esta é a STF que o guest reexecuta, a inclusão é válida por consenso e atestada pela prova; só a política do txpool (stubbed) poderia recusar.

**Recomendação.** Regra explícita na fronteira: `tx.chain_id != Some(spec.chain_id)` → `BlockExecutionError::ChainIdMismatch` (knob de configuração de cadeia, não mudança de EVM; há precedente em cadeias OP‑Stack). Alternativamente documentar a paridade com L1 e exigir a regra no txpool. Corrigir o doc de `Evm`.

#### C16 — `BLOCKHASH` devolve o placeholder `keccak256(número decimal)` do `EmptyDB` para toda a janela de 256 blocos: nenhum hash de bloco L2 é fornecido à EVM nem ao witness

**Severidade:** Médio (cético concorda). **Status:** Reproduzido. **Documentado:** não.

**Descrição.** `db.cache.block_hashes` nunca é populado; `BlockContext` não carrega hash pai/ancestrais; o crate não tem noção de hash de bloco L2. Para `1 <= number − n <= 256`, `Host::block_hash → CacheDB::block_hash (miss) → EmptyDB::block_hash_ref = keccak256(n.to_string())` (`revm-database-interface/src/empty_db.rs:110-112`); fora da janela o revm devolve zero antes de consultar o banco. Consequências: valor independente da história (duas cadeias com raízes distintas devolvem o mesmo `blockhash(0)`); **publicamente pré‑computável** para blocos futuros (PoC prevê `blockhash(123456789)`), tornando qualquer contrato que use `BLOCKHASH` para entropia/commit‑reveal deterministicamente explorável; placeholders são **inseridos** no cache e persistem em `L2State`/snapshots; host e guest concordam só porque ambos usam `CacheDB<EmptyDB>` — qualquer executor alternativo com hashes reais divergiria (split de consenso).

**Recomendação.** Definir o hash de bloco L2, fornecer ao executor o hash pai + até 256 ancestrais (ou provedor que **erre** fora da janela em vez de devolver placeholder), nunca deixar o fallback do `EmptyDB` alcançável, estender `BatchWitness` com os hashes, adicionar teste de conformidade e, até lá, documentar a não conformidade.

#### C17 — Chamada de sistema EIP‑4788 (beacon roots) no início do bloco e predeploy ausentes em `SpecId::CANCUN`

**Severidade:** Médio. **Painel:** cético classificou como Baixo (comportamento igual ao de outros L2 sem beacon chain, ex. Arbitrum Nitro; decisão de desenho ausente mais que erro). Mantido Médio pela divergência em relação ao "Cancun na gênese" anunciado e ao precedente OP‑Stack Ecotone citado pelo crate. **Status:** Reproduzido. **Documentado:** parcialmente (README lista predeploys como stubbed; a chamada de sistema e o campo `parent_beacon_block_root` não).

**Descrição.** O revm 41 delega deliberadamente as transições de fronteira de bloco ao cliente (`revm-handler/src/system_call.rs:1-13`, `SystemCallCommitEvm`). `execute_block` não as executa e `BlockContext` não tem campo para o valor. PoC: em L2 novo, `CALL` ao endereço `0x000F…Beac02` com timestamp de 32 bytes → `success=true`, saída vazia, 21.164 gás (no L1: raiz de 32 bytes ou REVERT); mesmo com o bytecode canônico instalado, o ring buffer nunca é escrito, enquanto a referência com `system_call_commit` do revm popula os dois slots. O Bloch é PoW sem beacon chain: o desenho precisa decidir o valor de 32 bytes (hash do bloco‑âncora Bloch? zero fixo?).

**Recomendação.** Decisão explícita e testada: (a) paridade Ecotone — `parent_beacon_block_root` em `BlockContext`, predeploy na gênese, `system_call_commit` após depósitos e antes da primeira tx, incluído no witness; ou (b) documentar o desvio nomeado ("sem EIP‑4788") com teste de fixação.

#### C18 — O livro de emissão zero (`total_minted_wei`) não é comprometido na raiz de estado, está ausente do witness e dessincroniza no guest; forjável por snapshot ou escrita direta em `db`

**Severidade:** Médio. **Painel:** cético classificou como Baixo (o livro é inerte: nenhum caminho de execução ou de prova o consome; nenhum desenho — Ethereum, OP‑Stack — compromete oferta na raiz; a solvência depende de autenticar depósitos, C10/C19). Mantido Médio porque o crate anuncia "total‑supply accounting" como funcionalidade **real** e a afirmação é inverificável a partir de qualquer compromisso. **Status:** Reproduzido. **Documentado:** não.

**Descrição e PoC.** Dois estados com o mesmo conjunto de contas e livros 5 BLCH vs 0 hasheiam para a mesma raiz; o guest começa de `L2State::new()` (livro 0) e termina com o livro igual só aos mints do lote; com a feature `serde` o campo privado é (des)serializado como dado simples sem checagem (snapshot editado para `total_minted_wei = 1` restaura sem erro); `L2State.db` é `pub`, logo `insert_account_info` cria saldo sem tocar o livro, contradizendo "esta é a ÚNICA forma de criar saldo nativo" (`state.rs:116`).

**Recomendação.** Guardar o acumulado mintado (e, com saques/queimas, o acumulado queimado ou o conjunto de depósitos consumidos) no storage de um predeploy de sistema, para que seja folha da raiz e seja carregado pelo witness; `total_minted_wei()` lê esse slot; tornar `db` não público (expor construtor de hidratação dedicado); validar snapshots contra a raiz ancorada; até lá, documentar que a contabilidade de oferta é telemetria do host.

#### C19 — O montante de escrow do depósito (`l1_sats`) é uma alegação não autenticada do chamador: `deposit_mint` só checa `mint_wei == sats_to_wei(l1_sats)`, nunca lê `l1_txid`/`l1_vout` e não impõe teto de oferta

**Severidade:** Médio. **Painel:** cético classificou como Baixo (na arquitetura pretendida a camada de derivação autentica depósitos, como no OP‑Stack; a STF confia neles). Mantido Médio porque a API não expressa a fronteira de confiança, não há teto, e o witness não compromete a lista de depósitos. **Status:** Reproduzido. **Documentado:** parcialmente — correção do cético: `state.rs:46-47` ("enforced by deposit_mint") é literalmente exato; as frases que **superestimam** são `state.rs:21` ("**provably** came from"), `:8-10`, `:56-57` ("never minting more than escrowed"), `:61-62` ("the wei the L1 escrow actually supports").

**Descrição.** `l1_sats` até `u64::MAX` é aceito e creditado (PoC: 184.467.440.737 BLCH em um depósito; o teste `max_sat_deposit_scales_without_overflow` fixa isso como intencional); `mint_wei` é totalmente redundante (para cada `l1_sats` só um `mint_wei` é aceito), acrescentando um modo de falha sem informação; nenhum tipo/trait expressa que o outpoint deve existir em bloco L1 finalizado, escrowar exatamente `l1_sats` e não estar consumido; `BatchWitness` não compromete os depósitos.

**Recomendação.** Remover `mint_wei` e derivar o crédito na STF; `MAX_L1_SATS` (teto duro de oferta do L1) por depósito e cumulativo; tipo de entrada que a camada de derivação **precisa** produzir (`AnchoredDeposit { l1_block_hash, height, inclusion_proof, outpoint, sats }` ou trait `L1EscrowOracle` com profundidade de finalidade); comprometer a lista de depósitos no witness/valores públicos; ler e impor o outpoint (C10); reescrever os docs listados.

#### C21 — `stateless_new_root`: recursão infinita (abort não capturável por stack overflow) com chave de extensão de comprimento zero em multiproof fornecido pelo host

**Severidade:** Médio. **Painel:** cético classificou como Baixo (no código atual não há call site não‑teste que passe proof não confiável a `stateless_new_root`; `generate_batch_witness` usa proof que ele mesmo construiu). Mantido Médio porque a função é a primitiva pública do guest e um abort não é contível por `catch_unwind`. **Status:** Reproduzido.

**Descrição.** `TrieNode::decode` de alloy‑trie só rejeita chave **codificada** vazia (`nodes/mod.rs:101`); o byte compacto `0x00` (flag EVEN, zero nibbles) decodifica como extensão com `key.len() == 0`. Em `collect_sparse` (`stateroot.rs:220-227`), `cp = path.join(&ext.key) == path`, `proof.contains_key(&cp)` é trivialmente verdadeiro e a recursão nunca termina nem cresce o caminho. PoC: `thread 'main' has overflowed its stack / fatal runtime error: stack overflow, aborting / EXIT 134`; o `catch_unwind` nunca retorna.

**Recomendação.** Rejeitar extensão com chave vazia; exigir que toda recursão estenda estritamente o caminho (`cp.len() > path.len()`) com `cp.len() <= 64`; contador de profundidade; converter para `Result`.

#### C22 — `stateless_new_root` entra em pânico ou, em release, viola o invariante de `Nibbles` com proof forjado: `collect_sparse` estende o caminho além de 64 nibbles com `push`/`join` sem checagem e `TrieNode::decode` sem guarda

**Severidade:** Médio. **Painel:** cético classificou como Baixo. Mantido Médio pelo comportamento indefinido em release. **Status:** Reproduzido (debug: pânicos via API pública; release: UB demonstrado em micro‑crate isolado; no binário real do release o nibble excedente foi silenciosamente descartado e a raiz devolvida sem crash — manifestação dependente de compilação).

**Descrição.** Três sumidouros em `collect_sparse`: `cp.push(nibble)` (`:238`) em ramo exposto num caminho de 64 nibbles → `push_unchecked` seta `len = 65` e `Nibbles::len()` faz `debug_assert!` + `core::hint::assert_unchecked(len <= 64)` (`nybbles/src/nibbles.rs:806-810`) — pânico em debug, **UB** em release, com `bit_pos = (64 − 64 − 1) × 4` em underflow de `usize` (`:940-951`); `path.join(&leaf.key)`/`path.join(&ext.key)` (`:219, :221`) → `assert!` em `extend_check` (pânico nos dois perfis); `TrieNode::decode(..).expect(..)` (`:217`) → chave compacta > 33 bytes faz `Nibbles::unpack` assertar dentro do decode antes que o `expect` possa converter em erro.

**Recomendação.** Checar `path.len() < 64` antes de `push` e `path.len() + key.len() <= 64` antes de `join`; pré‑validar o comprimento da chave compacta antes de decodificar; exigir chave completa de exatamente 64 nibbles para folhas da trie de contas; retornar `Result`. Não confiar em asserções de debug.

### 4.4 Baixos

#### C14 — `execute_block` tem semântica de verificador (qualquer tx de usuário inválida invalida o bloco), mas o papel não é documentado e não existe caminho de builder com validação/skip por tx

**Severidade:** Baixo (rebaixado de Médio). **Status:** Parcial — o comportamento foi reproduzido, mas a alegação normativa original ("a tx deveria ser pulada") só vale para um *block builder*; para uma STF de verificação (o que um guest SP1 precisa impor) a rejeição em nível de bloco é a semântica padrão de Ethereum/OP‑Stack, e o próprio `transact_many` do revm aborta na primeira tx inválida (`api.rs:89-107`). **Documentado:** não (nenhum papel é declarado; `BlockInput::txs` diz só "transações de usuário em ordem do sequenciador").

**O que falta.** Declarar o papel no doc de `execute_block`/`BlockInput::txs`; tornar a rejeição não destrutiva (C01/C02) para que o chamador possa remover a tx pelo `tx_index` e reconstruir; oferecer um ponto de entrada de builder (`build_block(...) -> (ExecutionOutcome, Vec<(usize, InvalidTransaction)>)`) que registre erros do revm como `Skipped` e continue — o que é sólido porque `catch_error` descarta o journal da tx falha (PoC: `[ok, skipped, ok]` com saldos/nonces/coinbase consistentes). Sem isso, um sequenciador construído diretamente sobre esta API precisa reexecutar o bloco inteiro O(n) vezes no pior caso, a blocos de 2 s, com gatilho de um único usuário.

#### C20 — `BatchWitness.pre_accounts` e `WitnessAccount.storage` são emitidos na ordem de iteração de `HashMap` com seed aleatória: o witness não tem forma canônica de bytes

**Severidade:** Baixo (rebaixado de Médio: sem impacto em solidez, raiz ou consenso — as partes canônicas `prev/new_state_root`, `proof: BTreeMap`, `changes: BTreeMap` são idênticas; `stateless_new_root` só consome os BTreeMaps e `hydrate_and_verify` é insensível à ordem). **Status:** Reproduzido — dois `L2State` construídos identicamente **no mesmo processo** já produzem ordens diferentes de contas e de slots (foldhash `RandomState` com seed por instância de mapa, `alloy-primitives/src/map/hasher.rs:39-40`, `foldhash/src/fast.rs:132-140`).

**Impacto.** Contradiz a "forma serde‑estável" alegada em `proving.rs:49-50`; bytes serializados não reproduzíveis para auditoria, comparação host/prover, deduplicação ou hash; mensagens de erro de `hydrate_and_verify` (primeira conta falha) não reproduzíveis; snapshots `serde` de `L2State` igualmente não canônicos.

**Recomendação.** Ordenar `pre_accounts` por endereço (ou por `keccak256(address)`) e cada `storage` por slot, ou usar `BTreeMap`; documentar a codificação canônica se o witness for hasheado; teste de determinismo.

#### C23 — `stateless_new_root`/`collect_sparse` e `hydrate_and_verify` entram em pânico (sem canal de erro) com witness malformado

**Severidade:** Baixo. **Status:** Reproduzido (6 formas). **Local:** `stateroot.rs:155-204, 210-247`; `proving.rs:182`.

**Formas reproduzidas.** (1) bytes não‑RLP/truncados em caminho exposto → `expect("valid trie node RLP")` (`:217`); (2) chave compacta > 33 bytes → asserção **dentro** de `TrieNode::decode` (`alloy-trie/nodes/mod.rs:167` → `Nibbles::unpack` `assert!(len <= 32)`) — propagar o erro do decode não bastaria; (3) caminhos > 64 nibbles (ver C22); (4) chaves de `changes` que não têm exatamente 64 nibbles ou estão em relação de prefixo com folha exposta/outro caminho → `assert!` em `HashBuilder::update`/`add_leaf` (`hash_builder/mod.rs:146, 164, 241`); (5) `WitnessAccount.code` iniciando com o mágico EIP‑7702 `0xEF01` inválido → `Bytecode::new_raw` = `new_raw_checked(..).expect(..)` (`revm-bytecode/src/bytecode/mod.rs:153-155`) aborta `hydrate_and_verify` antes de consultar o proof. Sub‑alegações **não** confirmadas: o `expect("proof node missing…")` (`:216`) é inalcançável (toda chamada é guardada por `contains_key`); `branch.stack[rank]` não pode sair dos limites em nó decodificado.

**Recomendação.** `Result<B256, WitnessError>` com enum de erros; pré‑validar tamanho de valores e chaves antes de `TrieNode::decode`; impor os limites de 64 nibbles; validar `changes` (64 nibbles, ordem estrita, sem prefixos) antes do `HashBuilder`; em `hydrate_and_verify` usar `Bytecode::new_raw_checked` e rejeitar qualquer código com prefixo `0xEF01` (impossível em estado Cancun).

#### C24 — `collect_sparse` ignora silenciosamente filhos inline (< 32 bytes): raiz errada sem erro para qualquer trie com folhas pequenas (tries de storage); a trie de contas não é afetada só porque suas folhas têm ≥ 70 bytes

**Severidade:** Baixo. **Status:** Reproduzido. **Documentado:** parcialmente — comentário em `stateroot.rs:242` "(account trie ≥32B)", mas a função é documentada como "geral sobre forma arbitrária de trie" (`:137-138`) e nada impõe a premissa.

**Descrição.** Quando um filho ausente do mapa é uma referência inline (`RlpNode::from_rlp` embute nós < 32 bytes; `as_hash()` devolve `None`), os braços `else if let Some(h) = …as_hash()` (`:224-226`, `:241-243`) não recorrem nem registram fronteira: o filho desaparece da reconstrução. PoC: trie de 3 folhas com valores de 2 bytes — *update* devolve a raiz de uma trie só com a folha alvo; *delete* de 1 de 3 devolve `EMPTY_ROOT_HASH`; em trie de storage com chaves hasheadas, dois slots cuja `keccak(slot)` compartilha 10 nibbles (encontrados por busca de aniversário em ~515 k hashes) e valor 1 produzem folhas inline de 30 bytes e raiz errada. Trie de contas de 300 contas: 412 nós, 0 inline, correto. O guest stateless real precisará atualizar tries de **storage** por conta — este walker não serve para isso.

**Recomendação.** Tornar `collect_sparse` total: para filho ausente com `as_hash() == None`, decodificar o nó embutido e processá‑lo em `cp` como exposto; ou restringir explicitamente à trie de contas com erro em filho inline e corrigir o doc; testes com tries de valores pequenos.

#### C25 — O executor rederiva o preço efetivo de gás sem consultar `tx_type`; um `TxEnv` legado/EIP‑2930 com `gas_priority_fee = Some(..)` faz `ExecutionOutcome::priority_fee_routed_wei` subnotificar o tip que o revm realmente pagou ao `SequencerFeeVault`

**Severidade:** Baixo. **Status:** Reproduzido. **Local:** `executor.rs:234-239, 266`; `revm-context-interface/src/transaction.rs:147-160` (`effective_gas_price` devolve `gas_price` incondicionalmente para tipos 0/1).

**Descrição.** `TxEnvBuilder::build` aceita `tx_type(Some(0|1))` com `gas_priority_fee(Some(..))` (`revm-context/src/tx.rs:512-520`, "do nothing") e o revm executa. PoC: tipo 0, `gas_price` 3 gwei, prioridade 1 gwei, basefee 1 gwei → cofre recebe 42.000.000.000.000 wei, outcome reporta 21.000.000.000.000; tipo 1 com `Some(0)` → cofre recebe 21 T wei, outcome reporta 0. Estado e raiz corretos; só o dado reportado (receita do sequenciador) está errado, e só para `TxEnv` cujo tipo é inconsistente com os campos.

**Recomendação.** Usar `tx.effective_gas_price(base_fee)` do próprio revm (calculado antes de `transact_commit` mover a tx), ou medir o delta de saldo do beneficiário antes/depois (robusto a mudanças futuras do revm); rejeitar na fronteira `TxEnv`s com tipo inconsistente. Observação relacionada: a igualdade de conservação verificada em §6 depende de `reservoir = 0` e `floor_gas = 0`, verdadeiro em Cancun; um upgrade para Prague (EIP‑7623 `floor_gas`) exigirá revisar a fórmula de roteamento.

#### C26 — As views de `L2State` reportam contas EIP‑161 vazias (tocadas) como existentes enquanto a raiz comprometida as exclui; contas fantasma e slots de valor zero nunca são podados e crescem sem limite

**Severidade:** Baixo. **Status:** Reproduzido. **Local:** `state.rs:143-153, 156-168, 171-178, 185-198`; `stateroot.rs:64-75, 94-115`; `executor.rs:276-291`.

**Descrição.** As views só testam `AccountState::NotExisting`, enquanto a raiz aplica EIP‑161 corretamente. Fantasmas surgem por operações baratas: CALL de valor zero a endereço nunca visto (21.000 gás; `commit_account` grava `Touched` com info padrão e nunca apaga — essa lógica vive em `revm::database::State`, que o crate não usa), CALL de valor zero a pré‑compilado, depósito de 0 sats ou crédito de taxa zero (`credit_balance` promove `NotExisting` → `None` mesmo com `amount_wei == 0`); todo slot apenas lido ou escrito para zero é gravado com valor 0. Consequências: RPC/explorer/prova construídos sobre `account()`/`balance_of` dizem que contas existem onde a raiz não as tem; crescimento ilimitado do estado em memória (~1.400 `DbAccount` permanentes por bloco de 30 M de gás), iterado por `account_leaves` a cada bloco e witness.

**Recomendação.** Um único predicado `exists(acc)` compartilhado por views e `account_leaves`; `credit_balance` não materializa conta com valor zero; podar após commit (`retain` em contas e slots) ou adotar `State`/`BundleState` do revm; teste de coerência view ⇔ folha.

#### C27 — A raiz de estado é reconstruída do zero sobre o estado inteiro a cada bloco, e `generate_batch_witness` clona profundamente o estado e reconstrói a trie ~5× por lote: custo O(contas + slots) independentemente do que o bloco tocou

**Severidade:** Baixo (escalabilidade/liveness; a raiz é correta e determinística). **Status:** Reproduzido (medições em release). **Documentado:** parcialmente (`executor.rs:401-404` reconhece o percurso completo).

**Medições.** Bloco **vazio**: 1,9 ms com 1 k contas, 20 ms com 10 k, 88 ms com 40 k, 417 ms com 160 k (~2,6 µs/conta, linear); 318 ms com 10 contas e um contrato intocado de 160 k slots (~2 µs/slot); witness de um lote de 1 depósito com 160 k contas: 2,2 s (~4,9× uma raiz completa). Extrapolado para 10 M de contas/100 M de slots, cada bloco — mesmo vazio — levaria dezenas de segundos e cada witness minutos mais uma cópia completa do estado. O crescimento é dirigido por atacante ao custo de gás (cada SSTORE novo adiciona ~2 µs a **todos** os blocos futuros).

**Recomendação.** Raízes de storage por conta em cache com invalidação pelo conjunto tocado; atualização esparsa/incremental da trie de contas (reutilizar `stateless_new_root` com nós retidos, ou `HashedPostState` + sparse trie estilo reth); em `generate_batch_witness`, calcular `account_leaves(pre)` uma vez, derivar o conjunto alterado do *write set* e evitar `pre.clone()`; documentar como mudança obrigatória para produção e adicionar benchmark.

#### C28 — `ChainSpec::gas_target`/`next_base_fee` dividem pelos knobs públicos `base_fee_elasticity` e `base_fee_denominator` sem checagem de zero; a guarda `target == 0` não cobre `elasticity == 0`

**Severidade:** Baixo (inalcançável a partir de entrada de bloco/tx/witness: o executor não chama essas funções; requer `ChainSpec` mal configurado). **Status:** Reproduzido (`panicked at chainspec.rs:86:9: attempt to divide by zero` para elasticidade 0 em ambas as funções — `gas_target()` é chamado em `:94` **antes** da guarda em `:95-97`; `:104:47` e `:109:29` para denominador 0; só o ramo `Equal` escapa; a guarda só é alcançável com `gas_limit < elasticity`).

**Recomendação.** Construtor validado / `ChainSpec::validate()` (rejeitar elasticidade 0, denominador 0, `gas_limit` 0, `gas_limit < elasticity`), campos privados ou builder; `checked_div` com fallback `parent_base_fee`; testes.

#### C29 — Depósitos são não medidos e ilimitados por bloco, e depósitos de 0 sats materializam entradas permanentes de conta (EIP‑161 vazias): crescimento de estado gratuito / amplificação de custo por bloco

**Severidade:** Baixo. **Status:** Reproduzido (release): 100.000 depósitos de 0 sats aceitos em um bloco em 60 ms, `gas_used = 0`, `state_root == EMPTY_ROOT_HASH`, mas `cache.accounts.len() == 100_000`, persistentes; após um bloco gratuito com 200.000 depósitos de 1 sat, um bloco **vazio** passou de ~24 µs para ~540 ms (×22.800); witness de 5 k depósitos de 1 sat sobre 50 k contas: 15.160 nós de proof, ~3 s. **Documentado:** não (o teste `zero_sat_deposit_is_exact_and_mints_nothing` fixa a criação de conta com 0 wei).

**Recomendação.** Crédito de zero wei como no‑op sem `load_account` (ou `DepositError::ZeroAmount`); `max_deposits_per_block` e/ou orçamento de gás de depósitos (precedente OP‑Stack) em `ChainSpec`, com transbordo carregado pela derivação para blocos seguintes; mínimo não‑dust no escrow L1; a longo prazo, C27.

#### C30 — O caminho no_std anunciado é não testado e nominal: `cargo test --no-default-features` não compila (34 erros) e revm/alloy‑trie são sempre construídos com `std` + backends C

**Severidade:** Baixo. **Status:** Reproduzido. **Detalhe.** `cargo build --no-default-features` compila (o código não‑teste é de fato livre de `std::`), mas o alvo de testes não: 32 usos de `vec!` sem importar a macro de `alloc` (`executor.rs`, `proving.rs`, `stateroot.rs:274`), `use std::collections::BTreeMap;` literal em `stateroot.rs:497` e E0282 consequente em `:527`. Logo a configuração no_std tem **zero** cobertura de testes e nenhum CI a exercita. No nível de dependências, `revm` e `alloy-trie` são declarados sem `default-features = false`, então `std`, `secp256k1`, `c-kzg`, `blst` (backends C/asm que não compilam para riscv32im) entram em toda configuração; a afirmação em `Cargo.toml:46` de que `std` "é no‑op no código do crate" é inexata (a feature alterna `#![no_std]` e imports de `alloc`). O argumento "reexecução byte‑idêntica" assume implicitamente que o guest pode usar outro conjunto de features do revm permanecendo byte‑idêntico — o conjunto de features determina o código compilado.

**Recomendação.** `#[cfg(test)] extern crate std;` em `lib.rs` (ou `use alloc::vec;` nos módulos de teste) e trocar o `use std::` em `stateroot.rs:497`; CI com `cargo build/test --no-default-features`; declarar dependências com `default-features = false` e reexpor features explicitamente (`std = ["revm/std", …]`), documentando o conjunto de features do guest (ex. `revm/kzg-rs`).

#### C31 — O contrato de determinismo ("nó/guest byte‑idênticos") só é imposto pelo `Cargo.lock`: `alloy-primitives`/`alloy-trie`/`alloy-rlp` são ranges caret, não há `rust-version` nem `rust-toolchain`, e a árvore fixada carrega backends C/asm e versões duplicadas

**Severidade:** Baixo. **Status:** Reproduzido. **Detalhe.** Só `revm = "=41.0.0"` é pin exato; `alloy-primitives = "1.6.0"`, `alloy-trie = "0.9"`, `alloy-rlp = "0.3"` (e `ruint`, a implementação de U256) são fixados apenas pelo lockfile. `cargo update --dry-run` moveria `alloy-primitives 1.6.1 → 1.7.2` e `ruint 1.19.0 → 1.20.0`; um crate separado com os mesmos requisitos (a forma do crate guest riscv32im descrito em `stubs.rs:63-70`) resolve hoje para 1.7.2/1.20.0/`blst 0.3.17`/`keccak 0.2.2` — 61 versões diferem. Executar o mesmo bloco sob as duas resoluções deu a **mesma** raiz (`0x1259e8aa…873d`): não há divergência semântica demonstrada, mas a byte‑identidade (e portanto a reprodutibilidade do vkey SP1) não é fornecida pelo manifesto. `README.md:30` erra o mecanismo: `revm-primitives 41.0.0` requer só `alloy-primitives ^1.5.2`; a unificação em 1.6.1 é artefato do lockfile. revm 41 exige `rust-version = "1.91.0"` (não declarado aqui); `Cargo.lock` versão 4 (cargo ≥ 1.78).

**Recomendação.** Pins exatos para todos os crates de consenso (`=1.6.1`, `=0.9.5`, `=0.3.16`, considerar `ruint =1.19.0`), tabela do README completa e corrigida; `rust-version` + `rust-toolchain.toml` com canal fixo (e o toolchain succinct quando o guest existir); `cargo build --locked` em CI; guest dentro do mesmo workspace ou diff de versões em CI; `cargo deny check bans` para duplicatas e backends nativos.

---

## 5. Observações informativas

Todas verificadas factualmente contra a árvore de trabalho (commit `4f0882e`).

* **I01 — Política de overflow inconsistente.** Em `executor.rs` os acumuladores `minted_wei += …` (`:183`), `base_fee_wei = … * …` (`:257`), `base_fee_routed += …` (`:263`), `priority_fee_routed += …` (`:266`) usam os operadores de `ruint`, que são **wrapping em debug e release** (`ruint/src/add.rs:234`, `mul.rs:192`, `macros.rs:11-20`; PoC: `U256::MAX + 1 == 0`), enquanto `state.rs` usa `checked_add().expect()` (`:127-130, 149-152, 189-193`). Nenhuma soma pode transbordar na prática (cada mint ≤ `u64::MAX × 10^10 < 2^98`), mas a postura "overflow explícito" não é uniforme.
* **I02 — `block_reward` é configuração morta.** Campo `pub` documentado "sempre zero" (`chainspec.rs:50-52`), lido apenas em `debug_assert_eq!` (`executor.rs:278`), nunca pago; em release um `ChainSpec { block_reward: 1, .. }` é aceito em silêncio; em debug a asserção dispara **depois** do `mem::take` e deixa `state.db` vazio (ver C01). Remover ou validar com erro duro.
* **I03 — Defaults do `TxEnvBuilder` (relato original inexato, corrigido).** O revm pré‑preenche `chain_id: Some(1)` e `gas_limit: 16_777_216` (EIP‑7825, não 30 M); com `tx_chain_id_check = true` uma tx sem `.chain_id(Some(spec.chain_id))` é rejeitada com `InvalidChainId` — direção segura. Observação: não há helper `validate_tx_for_spec(&ChainSpec, &TxEnv)` reunindo chain‑id, rejeição de blob e limite por tx.
* **I04 — Completude do storage‑root atrelada ao `EmptyDB`.** `storage_root`/`account_leaves` hasheiam só o que está no cache; isso é completo apenas porque `L2State.db` é `CacheDB<EmptyDB>`. Com qualquer `DatabaseRef` persistente, o `CacheDB` buscaria lazily e `compute_keccak_mpt_state_root` calcularia em silêncio uma raiz sobre estado parcial. Documentar a exigência e manter o tipo selado.
* **I05 — Documentação obsoleta.** (1) README `:35, :90` dizem 22 testes; há 40. (2) A raiz MPT e o witness ainda são descritos como *stubbed* em `Cargo.toml:8-10`, `executor.rs:5`, `state.rs:5, :86`, `stubs.rs:69-70, 82-84` (o stub `generate_execution_witness` faz sombra a `proving::generate_batch_witness`), `README.md:74-77`, `lib.rs:44-45`; nem README nem `lib.rs` listam `proving` ou `stateless_new_root` entre o que é real. (3) Comentários de teste contradizem o código implementado: `executor.rs:401-404` ("Stateless NEW‑ROOT does NOT work yet") e `stateroot.rs:383-396` ("step (b) … remaining P0.3 engineering") enquanto `stateless_new_root` existe e é testado. (4) Referências pendentes: `docs/specs/BLOCH-L2-EVM-DESIGN.md` (README `:6`, `Cargo.toml:4, :21`, `lib.rs:5`, `chainspec.rs:23`) e `BLOCH-L2-PROVER-SCOPE.md` (`Cargo.toml:49`, `executor.rs:392`, `stateroot.rs:118, :383`, `proving.rs:3`) não existem no repositório; `README.md:88` e `.cargo/audit.toml:3, :6` referenciam `l2/bloch-l2-evm`, layout que não é o deste repositório. (5) `DepositError::Scale` nunca é construído (`state.rs:64-65`); `chain_id` 700771 é placeholder declarado.
* **I06 — Alvos de vizinhos para *updates* puros inflam o proof.** `generate_batch_witness` (`proving.rs:102-118`) adiciona os dois vizinhos de **toda** chave alterada, embora só inserções/remoções reestruturem a trie; alloy‑trie 0.9.5 oferece `ProofRetainer::with_added_removed_keys` (retém nativamente o sobrevivente de colapso), não usado. Tamanhos medidos: 2.000 contas, 1 transferência + 1 deploy → 24 nós, 4.962 bytes (992 B/mudança); 100 transferências → 729 nós, 104.995 bytes (517 B/mudança). O "2‑3× de inflação" do relato original não foi medido isoladamente.
* **I07 — Denominador 250 a blocos de 2 s.** Variação máxima por bloco ±0,4 %; um minuto de blocos cheios leva 1 gwei a 1,127 gwei (+12,7 %) versus +80 % no Ethereum (denominador 8, 12 s); atingir 10× leva 577 blocos (~19 min). O OP Mainnet usa 250 com elasticidade 6; aqui a elasticidade é 2. Nota de revisão de parâmetros (janela barata para spam sustentado), não bug.
* **I08 — `.cargo/audit.toml`.** Duas das três justificativas descrevem caminhos de dependência errados: `tracing-subscriber` (RUSTSEC‑2025‑0055) e `derivative` (RUSTSEC‑2024‑0388) são entradas só‑lockfile, **nunca compiladas** (`cargo tree -i` → "nothing to print", mesmo com `--target all --all-features`); só `paste` (RUSTSEC‑2024‑0436) é de fato compilado como proc‑macro de `alloy-primitives`. Nenhum ignore é perigoso; a imprecisão enfraquece a rerevisão a cada bump. `cargo-audit` indisponível: a completude da lista **não foi revalidada**.
* **I09 — "serde‑stable shape" sem derives.** `WitnessAccount` e `BatchWitness` não têm derive `serde` (o único no crate é `L2State`); a feature `serde` não habilita `alloy-trie/serde` → `nybbles/serde`, logo `BTreeMap<Nibbles, _>` não serializaria mesmo com o atributo. Não há formato de fio host→guest definido nem teste de ida e volta.
* **I10 — Higiene.** Sem CI, sem `rustfmt.toml`/`clippy.toml`, sem `rust-version`; `cargo fmt --check` → 50 diffs (25 em `stateroot.rs`, 14 em `proving.rs`, 7 em `executor.rs`, 3 em `state.rs`, 1 em `scale.rs`); `cargo clippy --all-targets` → 13 avisos (11× `clone` em `Nibbles: Copy`, 1× `sort_by_key`, 1× `.into_iter()` explícito), nenhum de comportamento; `cargo build` e `cargo doc` limpos. Dois testes fixam limitações em vez de propriedades (`p0_stateless_read_…` com `assert_ne!` que falhará quando a lacuna for fechada; `host_generates_self_verifying_witness…` afirma só `changes.len() <= 4`). Sugestão de CI: `fmt --check`, `clippy -D warnings`, `test`, `test --all-features`, `build --no-default-features`, `build --locked`, `audit`.

---

## 6. O que foi verificado e está correto

Esta seção registra, com o mesmo rigor dos achados, o que os auditores examinaram e **confirmaram correto** (com PoC ou leitura das fontes vendorizadas). Serve para que o leitor saiba o que a auditoria cobriu, e não apenas o que encontrou.

**Executor e taxas (`executor.rs`, `state.rs`)**

* O tratamento de erro do próprio revm é correto: `Handler::run` roteia toda falha por `catch_error`, que chama `journal.discard_tx()` e nunca faz commit; `transact_commit` só faz `commit_inner()` após sucesso (`revm-handler/src/api.rs:143-147`, `handler.rs:557-566`). O banco dentro da EVM permanece consistente após uma tx inválida; a perda de estado de C01 é o crate descartando esse banco.
* Isolamento por transação: `JournalInner::finalize` faz `mem::take(state)` e limpa journal, logs e transient storage (`revm-context/src/journal/inner.rs:203-256`). O crédito direto ao `BaseFeeVault` entre transações não pode ser sobrescrito por estado obsoleto do journal.
* Regra de gás do bloco: `gas_usado_acumulado + tx.gas_limit <= gas_limit` com `saturating_add` corresponde à regra de Ethereum; um bloco com uma tx de `gas_limit` 30 M que usa 21 k seguida de outra de 21 k executa.
* A réplica do preço efetivo no executor é idêntica a `Transaction::effective_gas_price` (`revm-context-interface/src/transaction.rs:147-160`) para `TxEnv`s **bem formados** dos tipos 0/1/2 (exceção: C25). `priority > max_fee` e `max_fee < basefee` são rejeitados pelo revm.
* **Conservação de oferta em Cancun:** o chamador paga `effective × gas_limit`, recebe de volta `effective × (remaining + reservoir + refunded)`, o beneficiário recebe `(effective − basefee) × (used − reservoir)` e `tx_gas_used() = max((limit − remaining − reservoir) − refunded, floor_gas)`; em Cancun `reservoir = 0` (EIP‑8037 é Amsterdam) e `floor_gas = 0` (EIP‑7623 é Prague), logo `débito_líquido − pagamento_ao_beneficiário = basefee × tx_gas_used()` exatamente. Confirmado com PoC de SSTORE 0→1→0 (reembolso de 8.642 gás; cofres exatos; `total_native_wei == total_minted_wei`). A igualdade **depende do hardfork**.
* `deposit_mint` é atômico; `credit_balance` espelha `insert_account_info`. Nenhum pânico alcançável a partir de `TxEnv`s malformados (`u128::MAX`, `U256::MAX`, `gas_limit` 0/`u64::MAX`, nonce `u64::MAX`, initcode de 50 KB, access list de 1.000 chaves, `caller == coinbase`): todos retornam `Err`.

**Configuração da EVM (`Context::mainnet()` + `CfgEnv`)**

* Com as features padrão do revm 41 (`optional_*` desligadas), `balance_check`, `block_gas_limit`, `eip3541`, `eip3607`, `no_base_fee`, `priority_fee_check` e `fee_charge` são constantes de compilação e **não podem ser desligados**; `disable_nonce_check = false` e `tx_chain_id_check = true` por padrão (`revm-context/src/cfg.rs:321-349`).
* `chain_id = Some(outro)` rejeitado para todos os tipos; `None` rejeitado para tipos 1/2; `CHAINID` devolve 700771. EIP‑3607 rejeitado incondicionalmente. Nonce e saldo verificados. Tipo 4 rejeitado em Cancun (`Eip7702NotSupported`); tipo 3 rejeitado pelo executor; access lists aquecidas e cobradas.

**Raiz de estado keccak‑MPT (`stateroot.rs`)**

* RLP da conta byte‑idêntico ao `TrieAccount` de alloy‑trie; folhas ordenadas antes de `add_leaf`; estado vazio → `EMPTY_ROOT_HASH`.
* Raiz de storage igual a `alloy_trie::root::storage_root_unhashed` (slots reescritos para zero, valores ~2^256, slots limpos). Raiz de estado com storage real igual **bit a bit** à referência `state_root_unhashed` e igual a `ExecutionOutcome.state_root`.
* Semântica do conjunto de contas versus `CacheDB` (verificada pelo `execute_block` real): SELFDESTRUCT no mesmo tx de criação → excluída, destinatário creditado; SELFDESTRUCT em tx posterior → só move saldo; CREATE revertido → excluída, oferta conservada; CALL de valor zero a endereço novo/pré‑compilado → excluída da raiz (mas ver C26 para as views); transferência a pré‑compilado → incluída; depósito de 0 sats → excluído; coinbase com tip zero → excluído. Todas as raízes coincidem com a referência.

**Caminho de prova stateless — parte honesta**

* `verify_proof` em `hydrate_and_verify` é correto **para as folhas que hidrata**: adulterar o nó raiz ou a própria folha é detectado.
* Completude da regra de vizinhos para a trie de contas: réplica byte‑exata de `generate_batch_witness` sobre 22 formas construídas (primeira inserção em trie vazia, remoção da última conta, divisão de folha na profundidade 30, inserção divergindo no meio de uma extensão, remoção cujo sobrevivente é sub‑árvore ramo ou extensão→ramo, colapsos em cascata, remoção+inserção no mesmo ramo…) e **12.240 ensaios randomizados** (N ∈ {1,2,3,5,10,50,200}, alfabetos de 2/4/16 nibbles, 1–40 operações mistas): **0 divergências, 0 pânicos**. Para a trie de contas o gerador nunca retornou `Err("witness incomplete")` e por construção não devolve `Ok` com raiz errada.
* Semântica de `HashBuilder::add_branch` verificada por leitura e teste; a raiz é sempre retida pelo `ProofRetainer`.

**Escala, EIP‑1559 (`scale.rs`, `chainspec.rs`)**

* `sats_to_wei` não transborda (`u64::MAX × 10^10 < 2^98`); `wei_to_sats` nunca arredonda e mapeia o overflow para `SatsOverflow`.
* `next_base_fee` comparado a implementação de referência escrita a partir do texto da EIP‑1559 em **200.000 pares aleatórios** (incluindo `parent_base_fee` perto de `u64::MAX`): zero divergências; `max(1, …)` só no aumento; sem underflow no decremento; sem overflow em `u128`.

**Robustez**

* `expect("proof node missing…")` inalcançável; `branch.stack[rank]` seguro em nó decodificado; recursão limitada pelos 64 nibbles **exceto** C21; seleção de caminho em `hydrate_and_verify` correta (nós extras não reordenam nem causam falsa rejeição de folha honesta); `CacheDB<EmptyDB>::Error = Infallible`.

**Build e documentação da API**

* `cargo build` (padrão), `--no-default-features` e `--features serde` compilam sem avisos; `cargo doc --no-deps` limpo; `REVM_PIN` = `Cargo.toml` = `Cargo.lock`; lockfile não alterado por nenhum comando; SPDX em todos os `src/*.rs`; `#![deny(clippy::float_arithmetic)]` ativo; uma única versão de revm na árvore. Os 40 testes existentes afirmam o que dizem afirmar.

---

## 7. Lacunas da suíte de testes

Nenhuma destas lacunas escondeu um bug adicional além dos já listados (as PoCs correspondentes confirmaram o comportamento correto), mas todas reduzem a proteção contra regressão:

* **Caminhos de erro:** nenhum teste afirma `L2State` após `Err` (esconde C01/C02); nenhum teste de tipo de tx fora de {0,1,2,3}, de `chain_id` `None`/mismatch, de nonce/saldo inválido.
* **Raiz de storage:** `storage_root` só é exercitado com entrada vazia; o único contrato dos testes usa `MSTORE`, não `SSTORE`; `ExecutionOutcome.state_root` nunca é comparado a um cálculo independente; sem vetor de resposta conhecida nem diferencial contra `alloy_trie::root::*` (a PoC mostrou igualdade: `0x88a3bf90…bad89`).
* **Consenso/parâmetros:** `next_base_fee` testado só em cinco chamadas de passo único, nunca encadeado de um `ExecutionOutcome` para o próximo `BlockContext`; todos os testes usam `BlockContext::default()`; sem testes de propriedade (`proptest`) para `scale.rs` e `next_base_fee`.
* **Superfície EVM:** sem `CREATE2`, pré‑compilados, `SSTORE`/reembolsos, `SELFDESTRUCT`/EIP‑6780 (C11), tipo 4, depósito para contrato/cofre, chamador = coinbase. O roteamento de taxas só é validado em caminhos de 21 k gás.
* **Caminho de prova:** sem testes adversariais (proof não ancorado, nó injetado, conta omitida, duplicada, storage/código adulterados — C04/C05/C12); sem teste de determinismo do witness (C20); sem teste de `stateless_new_root` com proof vazio/estado vazio/remoção até vazio; sem teste de witness com inserções+remoções via `execute_block`.
* **Infra:** sem CI para no_std (C30) e feature `serde` (ida e volta de `L2State` nunca testada in‑tree; a PoC mostrou que preserva `total_minted_wei` e raiz).

O arquivo `tests/audit_regressions.rs` cobre os achados C01–C13, C15–C31 (C14 é decisão de desenho sem comportamento correto único).

---

## 8. Roteiro de correção recomendado

**P0 — antes de qualquer ancoragem, mesmo em testnet** — ✅ **aplicado, ver §0**

1. Atomicidade de `execute_block` (C01, C02, C14): validação pura antes de mutar; execução em cópia/camada bufferizada; escrita de volta só em `Ok`; testes de todo caminho de erro.
2. Whitelist de tipos de transação `{0,1,2}` e roteamento derivado do que o revm cobrou, com checagem de conservação por tx (C03, C25).
3. Proteção de replay de depósitos comprometida no estado (C10), remoção de `mint_wei`, teto `MAX_L1_SATS`, tipo de entrada autenticado (C19), livro de emissão em predeploy (C18).
4. **Redesenho do caminho de prova** antes de escrever o guest: `stateless_new_root(prev_state_root, proof, changes) -> Result` com ancoragem da raiz e encadeamento `keccak(filho) == referência` a cada descida (C04), erro em mudança dentro de sub‑árvore opaca ou remoção de chave não exposta (C08); banco rastreador no host e no guest com falha em *miss* e provas de exclusão para todo endereço tocado (C05, C06, C07); rejeição de contas vazias/duplicadas e checagem independente da raiz do proof em `hydrate_and_verify` (C12); API `verify_batch` que deriva `changes` no guest e nunca lê o do host (C09); alvos do proof = conjunto hidratado; autoverificação do host que hidrata e reexecuta. Considerar `reth-trie-sparse`.

**P1 — antes do testnet público**

5. Validação de cabeçalho na STF e cabeçalho nas entradas públicas do guest (C13); EIP‑155 obrigatório (C15); decisão sobre EIP‑4788 (C17); hashes de bloco reais para `BLOCKHASH` e no witness (C16).
6. Corrigir as afirmações "nunca queima" e rastrear `total_burned_wei` (C11).
7. Robustez do walker: `Result`, limites de 64 nibbles, rejeição de extensão vazia, pré‑validação antes de `TrieNode::decode`, `new_raw_checked`, filhos inline (C21, C22, C23, C24).

**P2 — qualidade e operação**

8. Predicado único de existência e poda pós‑commit ou `State`/`BundleState` (C26); medição de depósitos e no‑op para zero wei (C29); raiz incremental e witness sem clone (C27); `ChainSpec` validado (C28); witness canônico (C20).
9. Toolchain e build: no_std testado, dependências com `default-features = false`, pins exatos, `rust-toolchain.toml`, `--locked` em CI, `cargo deny`, CI completo (C30, C31, I10); atualizar toda a documentação obsoleta (I05, I08, I09) e a política de overflow (I01, I02).

---

## 9. Anexos

### 9.1 Testes de regressão (`tests/audit_regressions.rs`)

Um módulo por achado (`c01`…`c31`, exceto `c14`). Após as correções P0 (§0), os módulos dos achados corrigidos têm testes **ativos** que afirmam o comportamento correto contra a nova API e passam; os módulos dos achados ainda abertos continuam marcados `#[ignore = "..."]`, afirmam o comportamento esperado após a correção e falham hoje. Ao corrigir um achado, remova o `#[ignore]` do módulo.

```sh
cargo test                                          # unitários + regressões ativas, verde
cargo test --test audit_regressions -- --ignored    # achados ainda abertos (esperado: falhas)
cargo test --test audit_regressions c16 -- --ignored
```

### 9.2 Provas de conceito

As PoCs das fases de descoberta e verificação foram executadas em crates temporários (dependendo de `bloch-l2-evm` por caminho, com o mesmo `Cargo.lock`, perfil debug salvo onde indicado *release*) fora do repositório e não foram versionadas; suas saídas relevantes estão citadas em cada achado, e o comportamento essencial de cada uma está capturado pelo teste de regressão correspondente.

### 9.3 Fatos de referência verificados nas fontes vendorizadas

| Fato | Fonte |
|---|---|
| `tx_chain_id_check = true` por padrão; legada com `None` aceita | `revm-context/src/cfg.rs:325`; `revm-handler/src/validation.rs:139-147` |
| `TransactionType::Custom` (`≥ 5`) sem validação de taxa nem exigência de chain‑id | `revm-context-interface/src/transaction/transaction_type.rs:52-62`; `validation.rs:144, 209-211` |
| `reward_beneficiary` paga `(effective − basefee) × (used − reservoir)`; `reimburse_caller` devolve `remaining + reservoir + refunded` | `revm-handler/src/post_execution.rs:74-133` |
| `tx_gas_used() = max(spent − refunded, floor_gas)` | `revm-context-interface/src/result.rs:262-268` |
| `finalize` limpa journal/state/logs/transient storage por tx | `revm-context/src/journal/inner.rs:203-256` |
| `catch_error` → `discard_tx()`; `transact_commit` só comita em sucesso | `revm-handler/src/handler.rs:557-567`; `api.rs:143-147` |
| `commit_account`: selfdestruct → `NotExisting`; criada → `StorageCleared`; storage estendido com cada slot carregado | `revm-database/src/in_memory_db.rs:145-177` |
| EIP‑6780 selfdestruct‑para‑si na criação zera saldo sem crédito; log 7708 só em Amsterdam | `revm-context/src/journal/inner.rs:640-701`; `cfg.rs:145, 440-455` |
| `EmptyDB::block_hash_ref = keccak256(número decimal)` | `revm-database-interface/src/empty_db.rs:110-112` |
| EIP‑4788 delegado ao cliente (`SystemCallCommitEvm`) | `revm-handler/src/system_call.rs:1-13` |
| `U256 +`/`*` são wrapping | `ruint/src/add.rs:234`, `mul.rs:192`, `macros.rs:11-20` |
| `verify_proof` ancora só o primeiro nó e segue um único caminho; aceita prova de exclusão truncada em filho só‑hash | `alloy-trie/src/proof/verify.rs:47-73` |
| `TrieNode::decode` aceita extensão de chave vazia (`0x00`) e asserta em chave compacta > 33 bytes | `alloy-trie/src/nodes/mod.rs:99-125, 166-172` |
| `Nibbles::len()` usa `assert_unchecked` em release; `push_unchecked` sem checagem | `nybbles/src/nibbles.rs:806-810, 940-951` |
| `RlpNode` embute nós < 32 bytes; `as_hash()` = `None` para inline | `alloy-trie/src/nodes/rlp.rs:101-108, 148-150` |
| `HashMap` padrão de alloy‑primitives usa `foldhash::fast::RandomState` com seed por instância | `alloy-primitives/src/map/hasher.rs:39-40`; `foldhash/src/fast.rs:132-140` |
