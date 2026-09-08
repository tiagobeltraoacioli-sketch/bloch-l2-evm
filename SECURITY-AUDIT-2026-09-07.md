<!-- Amendment 2026-09-08: the historical audit below is preserved. -->
> **Atualização — 2026-09-08:** B01 recebeu uma interface implementada em
> `src/transactions.rs`: envelopes Ethereum canônicos, recuperação ECDSA e
> autenticação repetida em `verify_signed_batch`. A API antiga com `TxEnv`
> permanece de baixo nível e confiada. A integração obrigatória dessa interface
> no futuro nó/guest, os compromissos públicos de B03 e a derivação L1 de B02
> continuam pendentes. Ver [contrato de integração](WALLET-COMPATIBILITY.md).

# Auditoria de segurança — segunda revisão do Bloch L2 EVM

Revisão realizada em 7–8 de setembro de 2026 (UTC).
Base analisada: `c0ee0d7db11cced43098e19afbc9f405d97fefa2`.
Correções propostas na [PR #2](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm/pull/2).

## Parecer

O núcleo apresenta melhorias reais em relação à implementação descrita na
auditoria anterior, mas ainda continha falhas não cobertas pelos testes.
Esta revisão reproduziu dez regressões adversariais, agrupadas em cinco
achados, e implementou correções para esses cinco grupos. O código continua
sendo um **scaffold de transição de estado**, sem os componentes necessários
para operar um L2 com valor real.

O principal achado é uma falha de completude na atualização de uma trie
esparsa: autenticar a raiz anterior e a folha removida não garante que seja
possível calcular a raiz canônica seguinte. O verificador precisa conhecer
também o caminho compacto de um filho que sobreviva ao colapso de um ramo.
A correção rejeita uma prova insuficiente antes de construir a nova raiz.

Não se afirma verificação formal, conformidade EEST, resistência quântica
de ponta a ponta, ausência de outras vulnerabilidades ou auditoria externa
independente. A severidade abaixo descreve a consequência na API afetada;
as condições de exploração são indicadas separadamente.

## Escopo, método e limites

Foram inspecionados os nove módulos Rust, as duas implementações de trie,
o fluxo host/guest, a contabilidade, os testes existentes, o manifesto e
lockfile, a configuração de dependências e o workflow de CI. O relatório
`AUDITORIA-L2.md` foi tratado como histórico a ser verificado, não como
evidência suficiente de correção.

O método combinou revisão de fluxo de dados e de invariantes, leitura das
fontes versionadas das dependências relevantes, testes adversariais antes
das correções e comparação diferencial com reconstrução completa da trie.
Não foram acessados nós em produção, carteiras, chaves privadas ou fundos.
Os documentos de arquitetura citados como pertencentes a outro monorepo
não estão neste repositório e não foram auditados nesta revisão.

Rust não estava instalado no ambiente local. As compilações, os testes e
as verificações de dependências foram executados pelo GitHub Actions,
com o compilador `1.94.1` e `Cargo.lock` do projeto. Os resultados observados
estão registrados na seção de validação; um teste escrito não é apresentado
como teste executado sem a evidência correspondente.

## Modelo de confiança e invariantes

| Fronteira | Garantia exigida | Situação após esta PR |
|---|---|---|
| Raiz anterior → witness | A raiz pertence à cadeia aceita e cada leitura é autenticada | O núcleo autentica o witness contra a raiz recebida; o chamador ainda precisa autenticar essa raiz |
| Witness → nova raiz | Toda atualização aceita coincide com a MPT canônica do estado executado | Proteção adicional contra colapso com filho opaco; testes diferenciais |
| Ambiente → revm | Apenas regras Cancun e envelopes 0/1/2 estruturalmente válidos | Hardfork validado explicitamente; campos incompatíveis rejeitados |
| L1 → depósitos | Inclusão, valor, destinatário, ordem, finalidade e não reutilização do escrow | Ordem, escala e teto locais; autenticação da L1 ainda externa e não implementada aqui |
| Transação → remetente | Assinatura válida liga os bytes da transação ao remetente | `TxEnv.caller` continua sendo entrada confiada; recuperação de assinatura ausente |
| Execução → estado persistido | Erros não alteram contas, saldos ou a raiz de consenso | Overlay atômico preservado; o cache derivado da trie pode ser aquecido durante uma tentativa |
| Configuração → cabeçalho | Leitura e escrita usam o mesmo endereço de `block_info` | `head_at(spec.block_info)` corrige a divergência |

Para estados válidos derivados da gênese, a contabilidade pretende manter
`native = minted - burned`, com escala exata de `10^10` wei por sat,
depósitos ordenados por posição e taxas encaminhadas aos cofres. Essas
propriedades não provam que um depósito alegado realmente existe na L1.
Snapshots arbitrários e escrita por `db_mut()` também não recebem, nesta
PR, uma prova global de validade econômica.

## Achados corrigidos

| ID | Severidade e alcance | Causa | Correção |
|---|---|---|---|
| D01 | Alta, integridade da raiz stateless; caminho de exclusão também exercitado em Cancun | Filho opaco tratado como hash de ramo após exclusão de seu último irmão | Exigir expansão do filho quando seu pai perder todos os outros filhos |
| D02 | Média, parser de witness; requer que bytes malformados cheguem à etapa de decodificação | Limite em bytes não considera paridade; codificações não canônicas e bytes finais são aceitos | Pré-validação da aridade, comprimento em nibbles, flags, padding e consumo integral; regras de forma e referências |
| D03 | Média, configuração de consenso | `spec_id` público aceita forks diferentes do Cancun declarado | `ChainSpec::validate()` rejeita qualquer outro hardfork |
| D04 | Média, fronteira do ambiente de transação | Whitelist do tipo não impede campos de outros envelopes | Rejeitar access list em tipo 0 e autorizações EIP-7702 nos tipos 0/1/2 |
| D05 | Baixa, disponibilidade e correção de helpers | `BlockContext::next()` lê endereço padrão e soma altura sem proteção | Adicionar `head_at()`, usar o endereço configurado e saturar a altura terminal para rejeição pelo executor |

### D01 — Inclusão autenticada não basta para atualizar uma trie após exclusão

Na versão base, `SparseTrieView::descend()` armazenava qualquer filho não
revelado como `(caminho, hash)`. `apply()` entregava todos esses elementos a
`HashBuilder::add_branch()`, sem verificar se uma exclusão mudava a forma
do pai. Um filho não revelado pode ser uma folha ou uma extensão.

Exemplo mínimo: uma raiz com duas folhas, uma sob o nibble `0` e outra sob
`1`. A prova revela somente a primeira. Após removê-la, a raiz correta é
a folha sobrevivente com seu caminho compacto ampliado. Usar seu hash antigo
sob uma nova extensão não realiza essa fusão. A autenticação de todos os
bytes fornecidos continua correta; o erro está na reconstrução.

O mesmo problema aparece quando o sobrevivente é uma extensão: é necessário
fundir prefixos, e o hash não revela o prefixo interno. Os dois casos são
cobertos por `deletion_requires_the_opaque_surviving_leaf` e
`deletion_requires_the_opaque_surviving_extension`.

A correção registra quais elementos opacos são filhos diretos de ramos.
Após aplicar as mudanças e ordenar os elementos sobreviventes, seus vizinhos
imediatos indicam se ainda existe outro filho sob o pai original. Se não,
a operação retorna `OpaqueChildNeedsExpansion`. Revelar esse nó permite
aplicar a exclusão e obter a raiz da reconstrução completa. Não é necessário
revelar o estado inteiro.

Justificativa: em ordem lexicográfica, o maior prefixo comum com outra chave
ocorre em um vizinho imediato. Como folhas e fronteiras são disjuntas, um
vizinho sob o prefixo do pai implica um filho distinto sobrevivente. O teste
de sobrevivência não introduz uma comparação quadrática entre todos os pares.

**Alcance:** `stateless_new_root()` é pública e anuncia suporte a exclusões
genéricas. O gerador honesto já acrescentava vizinhos para mudanças
estruturais; isso não constituía validação de um host adversarial.
Embora Cancun não exclua contratos criados em transações anteriores,
[EIP-6780](https://eips.ethereum.org/EIPS/eip-6780) permite remover uma conta
previamente financiada quando um contrato é criado e destruído nela na
mesma transação. A regressão de integração cobre exatamente esse caso:
financia o endereço futuro, executa `CREATE` com `ADDRESS; SELFDESTRUCT`,
confirma a exclusão e remove apenas os nós da prova que não são necessários
para autenticar as contas lidas. A hidratação continua válida; a atualização
deve rejeitar a falta do irmão necessária ao colapso. Não se afirma um
ataque em rede implantada nem extração de fundos; o defeito é de integridade
da raiz calculada pelo verificador.

### D02 — Caminho de 33 bytes pode conter 65 nibbles

O limite anterior de 33 bytes incluía corretamente caminhos pares de 64
nibbles, mas também deixava passar caminhos ímpares de 65 nibbles. A rotina
da dependência desempacotava os 64 nibbles restantes e tentava concatenar
o primeiro nibble antes de a checagem posterior de comprimento ser executada.
O CI reproduziu o pânico em `nybbles-0.4.8/src/nibbles.rs`.

A nova checagem usa `2 * (compact_len - 1) + odd <= 64` **antes** do decoder.
Também exige flags válidas e padding zero em caminhos pares. O parser exige
que os bytes representem exatamente um item RLP e conta no máximo 17 itens
antes de chamar o decoder que materializa a lista.

Foram reforçadas ainda as regras: ramos com pelo menos dois filhos;
extensões reveladas terminam em ramos; raiz vazia apenas na raiz; nós
embutidos menores que 32 bytes e nós revelados por referência hash com
pelo menos 32 bytes. Subárvores não reveladas continuam dependendo da
premissa de uma raiz anterior canônica e autenticada.

As regressões cobrem paridade, padding, bytes finais, formas estruturais
e um corpus determinístico de 18.176 entradas curtas. Esse corpus não é
fuzzing contínuo nem prova de totalidade para toda entrada possível.
O achado é condicionado à decodificação de dados malformados: para uma raiz
canônica previamente autenticada, um atacante não pode simplesmente trocar
o nó raiz sem falhar na verificação do hash.

### D03 — O fork declarado não era imposto pela configuração

`ChainSpec::validate()` verificava vários parâmetros, mas não `spec_id`.
O executor passava esse valor diretamente a
`set_spec_and_mainnet_gas_params()`. Assim, a API aceitava configurações
Shanghai ou Prague apesar de declarar execução Cancun, sem mecanismo de
ativação de upgrade e mantendo a mesma fronteira de tipos de transação.

Agora somente `SpecId::CANCUN` é aceito. Outros forks retornam
`UnsupportedHardfork` antes da execução. Isso protege contra divergências
de configuração; não substitui autenticação da configuração inteira pelo
programa de prova e pelo verificador de liquidação.

### D04 — Tipos aceitos ainda carregavam campos incompatíveis

`TxEnv` é um ambiente já decodificado, com campos públicos. O chamador pode
alterar `tx_type` depois do builder. A checagem existente rejeitava blobs e
inconsistência de priority fee, mas permitia access lists em transações
legadas e autorizações EIP-7702 nos tipos 0/1/2.

A validação agora rejeita essas combinações. Uma transação tipo 1 continua
podendo ter access list vazia, e os tipos 1/2 continuam podendo carregá-la.
Não se afirma que autorizações escondidas executavam EIP-7702 em Cancun:
o achado comprovado é a aceitação de um ambiente que não corresponde ao
envelope declarado. Recuperação de assinatura continua fora do escopo
implementado, como explicado em B01.

### D05 — Endereço configurado e altura terminal

O executor lia e escrevia `spec.block_info`, mas o helper `next()` chamava
`state.head()`, que lê o endereço padrão. Com endereço próprio, o segundo
contexto era construído como o primeiro bloco; o teste observou altura `1`
onde era esperada `2`. `L2State::head_at()` agora oferece a leitura correta,
preservando `head()` como conveniência para o endereço padrão.

Em uma cabeça com altura `u64::MAX`, a soma do helper causava pânico em
debug. Agora ela satura. O executor já usa `checked_add()` e rejeita o bloco
seguinte, impedindo wraparound e mantendo o estado de consenso intacto.
O helper não transforma a altura terminal em um bloco executável.

## Pendências de arquitetura e operação

Estes pontos impedem tratar o resultado como um L2 pronto para valor real.
Não são declarados resolvidos pelas correções locais acima.

| ID | Pendência | Evidência e ação necessária |
|---|---|---|
| B01 | Autenticação das transações | `BlockInput.txs` contém `TxEnv`; o remetente é fornecido. Verificar envelopes assinados e ligar os bytes autenticados ao que o guest executa |
| B02 | Autenticação dos depósitos e da L1 | Posição crescente e teto não provam escrow. Derivar destinatário/valor/outpoint de dados autenticados, impor finalidade, completude da inbox e política de reorg |
| B03 | Statement de prova e compromissos incompletos | `verify_batch()` recebe configuração e raiz do chamador; não existe guest SP1 nem verificador de liquidação. Fixar identidade do programa, configuração, raiz anterior aceita e dados do lote em valores públicos verificados |
| B04 | Cabeçalho não compromete transações nem recibos | `L2Header` contém raiz de estado e depósitos, mas não transaction root ou receipts root. Blocos com efeitos iguais podem diferir em bytes ou logs. Definir o cabeçalho de protocolo e seus compromissos antes de integração com RPC/provas |
| B05 | Witness de armazenamento escala com a conta inteira | Cada `WitnessAccount` carrega todos os slots não zero. Tocar poucos slots de um contrato grande pode produzir witness grande. Medir esse caso e projetar provas de armazenamento por acesso com limites de recursos |
| B06 | Timestamps repetidos substituem a entrada de âncora | A regra permite timestamps iguais e `next()` os preserva; o contrato EIP-4788 indexa pelo timestamp. Definir uma regra temporal que evite ambiguidade ou documentar precisamente a substituição e sua consequência para consumidores |
| B07 | Persistência, bridge e disponibilidade de dados ausentes | Estado é `InMemoryDB`; vaults são contas sem lógica de saque; nó, RPC, txpool e guest são stubs. Implementar recuperação de falhas, contratos, publicação de dados e verificação independente antes de operação |
| B08 | Confiança em snapshots e inicialização | `db_mut()` e desserialização não validam globalmente oferta, código, metadados de sistema e raízes contra um checkpoint. Tratar importações como entrada privilegiada até existir um carregador autenticado |

A classificação anterior de C19 como corrigido precisa ser interpretada
restritamente: escala, ordenação e limite monetário foram melhorados, mas
**não autenticam a existência do depósito**. De modo semelhante, o cursor
impede reuso da mesma posição; sem derivação autenticada, não impede que o
mesmo outpoint seja reapresentado com outra posição alegada.

O token de gás continuar sendo BLCH bridgeado não torna as contas EVM
pós-quânticas. Transações Ethereum usuais dependem de assinaturas ECDSA,
e o simples compromisso em uma L1 não modifica essa autenticação. A futura
prova SP1 precisa de avaliação própria do programa, backend, parâmetros e
verificador. Nenhuma dessas propriedades é certificada nesta auditoria.

As verificações de dependências usam as exceções já presentes no projeto:
`cargo audit` ignora `RUSTSEC-2025-0055`, `RUSTSEC-2024-0388` e
`RUSTSEC-2024-0436`; `cargo deny` ignora `RUSTSEC-2024-0436`. Esta PR não
adiciona exceções. O sucesso desses comandos significa ausência de erros
segundo essa política configurada, não ausência universal de riscos na
árvore de dependências. O scan observado analisou 292 dependências do
lockfile. Não foi realizada uma nova auditoria criptográfica dessas crates.

### Critérios concretos para a próxima etapa

1. Ligar o remetente aos bytes assinados dentro do statement verificado.
   Validar assinaturas apenas no host não protege contra um host adversarial.
2. Especificar a derivação da inbox da L1 e demonstrar inclusão, completude,
   ordenação e comportamento em reorg com fixtures adversariais.
3. Definir uma codificação versionada dos valores públicos e um verificador
   que fixe programa, configuração, raiz anterior aceita, dados do lote e
   âncoras. Exercitar troca de configuração, replay e substituição do lote.
4. Compilar e executar o guest real, incluindo o backend KZG escolhido,
   com testes diferenciais host/guest. `no_std` testado em x86_64 não é
   evidência de execução bem-sucedida no alvo RISC-V.
5. Implementar persistência atômica e recuperação de falhas para contas,
   raiz, cabeça e cursor; testar interrupção de escrita e rollback de reorg.
6. Medir custos com contratos de armazenamento grande, estabelecer limites
   de witness/transporte e executar EEST e fuzzing contínuo antes de avaliar
   a liberação para valor real.

## Compatibilidade e custo das correções

Não há nova dependência nem alteração do lockfile, do hardfork efetivamente
usado pelo testnet padrão, dos endereços padrão ou da política de taxas.
Entradas malformadas e configurações fora de Cancun passam a ser rejeitadas.
Provas de inclusão que não bastam para uma exclusão estrutural precisam
revelar o filho sobrevivente. Isso é uma mudança deliberada de aceitação
do verificador; consumidores com `match` exaustivo dos enums de erro precisam
tratar as variantes adicionais.

O teste de fronteiras opera sobre o conjunto exposto, preservando a ordenação
`O(n log n)` existente; a consulta ao conjunto de fronteiras custa
`O(log n)` por elemento. O parser limita a quantidade de itens antes da
decodificação, mas não estabelece um limite global de bytes de witness.
Limites de transporte, memória e ciclos do prover continuam pendentes.

Estas alterações devem ser consideradas uma revisão do programa de prova
quando esse programa existir. Não se deve reutilizar uma identidade/vkey
calculada para um executável diferente, mesmo quando casos válidos mantêm
os mesmos resultados.

## Validação reproduzível

Baseline com testes novos, antes de correções:
`d3f1bef339802cc1d8eaecd14d3e96c91381b230`.
O [CI de reprodução](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm/actions/runs/34170856275)
compilou, passou fmt e Clippy, passou os 68 testes unitários e os 34 testes
ativos da auditoria anterior, e falhou nos dez novos testes adversariais.
O benchmark já ignorado permaneceu ignorado. Portanto, a falha não foi
inferida apenas de uma mensagem de compilação ou de formatação.

A suíte final acrescenta controles positivos, 1.600 combinações de provas
parciais/exclusões comparadas ao `alloy_trie::HashBuilder`, o corpus de
entradas malformadas e oito blocos com endereços de sistema próprios,
comparando guest, gerador e execução completa. Esses testes são direcionados
às mudanças; não substituem ethereum/tests, EEST ou uma campanha de fuzzing.

Comandos de verificação:

```sh
cargo fmt --all -- --check
cargo build --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --features serde
cargo build --locked --no-default-features
cargo test --locked --no-default-features
cargo test --locked --release --test deep_security
cargo doc --locked --no-deps
cargo audit
cargo deny check bans sources advisories licenses
```

O [CI após as correções](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm/actions/runs/34171748477)
passou integralmente no commit `02b66388d69bb0baf98093e41714b6b6571c6a1e`:

| Verificação | Resultado observado |
|---|---|
| Build, fmt e Clippy, incluindo todos os targets/features | Aprovados |
| Testes padrão | 68 unitários + 34 da auditoria anterior + 16 novos = 118 aprovados |
| Testes com `serde` | 69 + 34 + 16 = 119 aprovados |
| Build e testes sem features padrão | Build aprovado; 118 testes aprovados |
| Novas regressões em `release` | 16 aprovadas |
| Documentação Rust | Aprovada |
| `cargo audit` e `cargo deny` | Aprovados sob a política de exceções descrita acima |

O benchmark de desempenho preexistente permaneceu ignorado em todas as
configurações; não foi usado como evidência de desempenho desta revisão.
O caso Cancun de conta previamente financiada passou nas quatro execuções
da nova suíte. O commit final de documentação apenas registra a evidência
e esclarece comentários, sem alterar comportamento executável.

O teste de release foi adicionado ao workflow para manter a proteção contra
regressões que diferem entre builds com e sem otimizações.

## Fontes primárias consultadas

- Código base: [commit c0ee0d7](https://github.com/tiagobeltraoacioli-sketch/bloch-l2-evm/tree/c0ee0d7db11cced43098e19afbc9f405d97fefa2).
- Decoder e caminhos compactos: [alloy-trie 0.9.5, nodes/mod.rs](https://docs.rs/alloy-trie/0.9.5/src/alloy_trie/nodes/mod.rs.html).
- Reconstrução de trie: [alloy-trie 0.9.5, HashBuilder](https://docs.rs/alloy-trie/0.9.5/src/alloy_trie/hash_builder/mod.rs.html).
- Ambiente de transação: [revm-context 41.0.0, TxEnv](https://docs.rs/revm-context/41.0.0/src/revm_context/tx.rs.html).
- Âncoras por timestamp: [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).
- Exclusão na criação de contratos: [EIP-6780](https://eips.ethereum.org/EIPS/eip-6780).
- Assinatura e domínio da transação: [EIP-155](https://eips.ethereum.org/EIPS/eip-155).
