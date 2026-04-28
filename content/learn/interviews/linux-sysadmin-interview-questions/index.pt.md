---
title: "Entrevista Linux SysAdmin: Processos, Permissões e Redes"
description: "20 perguntas essenciais de entrevista de administração de sistemas Linux para funções Senior SysAdmin e DevOps. Abrange permissões de arquivos, gerenciamento de processos, systemd, redes e resolução de problemas."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Entrevista Linux SysAdmin: Processos, Permissões e Redes",
    "description": "20 perguntas essenciais de entrevista de administração de sistemas Linux sobre permissões, processos, systemd e redes.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

A administração de sistemas Linux é a base da infraestrutura moderna. Seja para uma entrevista para um cargo de SysAdmin, DevOps, SRE ou Cloud Engineer, você será testado em sua capacidade de gerenciar usuários, solucionar problemas de processos, configurar redes e proteger servidores — tudo pela linha de comando. Este guia cobre 20 perguntas que separam candidatos seniores dos juniores, com respostas que demonstram experiência operacional real.

**Precisa de uma referência rápida de comandos?** Mantenha nosso [Cheatsheet Linux SysAdmin](/cheatsheets/linux-sysadmin-permissions/) aberto durante sua preparação.

---

## Permissões e Propriedade de Arquivos

<details>
<summary><strong>1. Explique o modelo de permissões do Linux (rwx, notação octal, bits especiais).</strong></summary>
<br>

Todo arquivo tem três níveis de permissão: **Proprietário**, **Grupo**, **Outros**. Cada nível pode ter **Leitura (r=4)**, **Escrita (w=2)**, **Execução (x=1)**.

A notação octal combina esses valores: `chmod 755` = rwxr-xr-x (proprietário: total, grupo/outros: leitura+execução).

**Bits especiais**:
- **SUID (4000)**: O arquivo é executado como o proprietário do arquivo, não como o usuário que o executa. Exemplo: `/usr/bin/passwd` é executado como root para que os usuários possam alterar sua própria senha.
- **SGID (2000)**: Em arquivos, é executado como o grupo proprietário. Em diretórios, novos arquivos herdam o grupo do diretório.
- **Sticky bit (1000)**: Em diretórios, apenas o proprietário do arquivo pode excluir seus arquivos. Exemplo clássico: `/tmp`.
</details>

<details>
<summary><strong>2. Qual é a diferença entre hard links e soft links?</strong></summary>
<br>

- **Hard link**: Uma referência direta ao inode (os dados reais no disco). Múltiplos hard links para o mesmo arquivo compartilham o mesmo número de inode. A exclusão de um hard link não afeta os outros — os dados persistem até que todos os hard links sejam removidos. Não pode cruzar limites de sistema de arquivos. Não pode vincular a diretórios.
- **Soft link (symlink)**: Um ponteiro para um caminho de arquivo (como um atalho). Tem seu próprio inode. Se o arquivo de destino for excluído, o symlink se torna um link pendente. Pode cruzar sistemas de arquivos. Pode vincular a diretórios.

Use `ls -li` para ver os números de inode e confirmar as relações entre hard links.
</details>

<details>
<summary><strong>3. Um desenvolvedor não consegue escrever em um diretório compartilhado. Como você diagnostica e resolve o problema?</strong></summary>
<br>

Passos de diagnóstico:
1. `ls -la /shared/` — verificar propriedade e permissões.
2. `id developer` — verificar a quais grupos o usuário pertence.
3. `getfacl /shared/` — verificar ACLs que possam sobrescrever permissões padrão.

Soluções comuns:
- Adicionar o usuário ao grupo do diretório: `sudo usermod -aG devteam developer`.
- Definir SGID no diretório para que novos arquivos herdem o grupo: `chmod g+s /shared/`.
- Se ACLs forem necessárias: `setfacl -m u:developer:rwx /shared/`.
- Garantir que o umask não esteja bloqueando a escrita do grupo (verificar com o comando `umask`).
</details>

<details>
<summary><strong>4. O que é umask e como afeta a criação de arquivos?</strong></summary>
<br>

`umask` define as permissões padrão **removidas** de novos arquivos e diretórios. É uma máscara de bits subtraída das permissões máximas.

- Máximo padrão para arquivos: 666 (sem execução por padrão).
- Máximo padrão para diretórios: 777.
- Com `umask 022`: arquivos obtêm 644 (rw-r--r--), diretórios obtêm 755 (rwxr-xr-x).
- Com `umask 077`: arquivos obtêm 600 (rw-------), diretórios obtêm 700 (rwx------).

Definido em nível de sistema em `/etc/profile` ou por usuário em `~/.bashrc`. Crítico para segurança — um umask permissivo pode expor arquivos sensíveis a usuários não autorizados.
</details>

## Gerenciamento de Processos

<details>
<summary><strong>5. Explique a diferença entre um processo, uma thread e um daemon.</strong></summary>
<br>

- **Processo**: Uma instância de um programa em execução com seu próprio espaço de memória, PID, descritores de arquivo e ambiente. Criado por `fork()` ou `exec()`.
- **Thread**: Uma unidade de execução leve dentro de um processo. Threads compartilham o mesmo espaço de memória e descritores de arquivo, mas têm sua própria pilha e registradores. Mais rápidas de criar do que processos.
- **Daemon**: Um processo em segundo plano que é executado sem um terminal de controle. Tipicamente iniciado no boot, é executado continuamente e fornece um serviço (sshd, nginx, cron). Convencionalmente nomeado com o sufixo `d`.
</details>

<details>
<summary><strong>6. O que são processos zumbis e como você os trata?</strong></summary>
<br>

Um **zumbi** é um processo que terminou a execução mas ainda tem uma entrada na tabela de processos porque seu pai não chamou `wait()` para ler seu status de saída. Não consome recursos exceto um slot de PID.

Identificar zumbis: `ps aux | grep Z` — eles mostram status `Z` (defunct).

Você **não pode** matar um zumbi — ele já está morto. Para removê-lo:
1. Envie `SIGCHLD` ao processo pai: `kill -s SIGCHLD <parent_pid>`.
2. Se o pai ignorar, matar o processo pai tornará o zumbi órfão, que será adotado por `init` (PID 1). O init automaticamente chama `wait()` e o limpa.

Um grande número de zumbis geralmente indica um processo pai defeituoso que não está recolhendo seus filhos.
</details>

<details>
<summary><strong>7. Explique os sinais do Linux. O que são SIGTERM, SIGKILL e SIGHUP?</strong></summary>
<br>

Sinais são interrupções de software enviadas a processos:

- **SIGTERM (15)**: Solicitação de terminação educada. O processo pode interceptá-lo, limpar recursos e sair graciosamente. Isto é o que `kill <pid>` envia por padrão.
- **SIGKILL (9)**: Terminação forçada. Não pode ser interceptado, bloqueado ou ignorado. O kernel termina o processo imediatamente. Use apenas como último recurso — nenhuma limpeza possível.
- **SIGHUP (1)**: Historicamente "desligamento". Muitos daemons (nginx, Apache) recarregam sua configuração quando recebem SIGHUP, em vez de reiniciar.
- **SIGINT (2)**: Interrupção, enviado por Ctrl+C.
- **SIGSTOP/SIGCONT (19/18)**: Pausar e retomar um processo.
</details>

<details>
<summary><strong>8. Como você encontra e mata um processo que consome muita CPU?</strong></summary>
<br>

1. Identificar o processo: `top -o %CPU` ou `ps aux --sort=-%cpu | head -10`.
2. Obter detalhes: `ls -l /proc/<pid>/exe` para ver o binário real.
3. Verificar o que está fazendo: `strace -p <pid>` para chamadas de sistema, `lsof -p <pid>` para arquivos abertos.
4. Parada graciosa: `kill <pid>` (SIGTERM) — permitir limpeza.
5. Parada forçada: `kill -9 <pid>` (SIGKILL) — apenas se SIGTERM falhar.
6. Prevenir recorrência: Se gerenciado por systemd, definir `CPUQuota=50%` no arquivo unit do serviço.
</details>

## Systemd e Serviços

<details>
<summary><strong>9. O que é systemd e como ele difere do SysVinit?</strong></summary>
<br>

**SysVinit**: Processo de inicialização sequencial usando scripts shell em `/etc/init.d/`. Os serviços iniciam um após o outro em um nível de execução definido. Tempos de inicialização lentos. Simples mas com gerenciamento limitado de dependências.

**systemd**: Processo de inicialização paralelo usando arquivos unit. Suporta dependências, ativação por socket, início de serviços sob demanda, cgroups para controle de recursos e journald para logging. Inicialização muito mais rápida. Gerencia serviços, timers, montagens, sockets e targets.

systemd é o sistema init padrão no RHEL, Ubuntu, Debian, Fedora, SUSE e Arch.
</details>

<details>
<summary><strong>10. Como você cria um serviço systemd personalizado?</strong></summary>
<br>

Crie um arquivo unit em `/etc/systemd/system/myapp.service`:

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Depois: `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

Valores chave de `Type`: `simple` (padrão, processo principal executa em primeiro plano), `forking` (processo faz fork para segundo plano, precisa de `PIDFile`), `oneshot` (executa uma vez e termina), `notify` (processo sinaliza prontidão via sd_notify).
</details>

<details>
<summary><strong>11. Como você analisa o desempenho de inicialização com systemd?</strong></summary>
<br>

- `systemd-analyze` — tempo total de inicialização.
- `systemd-analyze blame` — lista de serviços ordenados por tempo de início.
- `systemd-analyze critical-chain` — árvore do caminho crítico de inicialização.
- `systemd-analyze plot > boot.svg` — gerar uma linha do tempo visual da sequência de inicialização.
- `journalctl -b -p err` — erros da inicialização atual.

Para acelerar a inicialização: desabilitar serviços desnecessários (`systemctl disable`), mudar serviços para ativação por socket (início sob demanda) e identificar serviços lentos na saída do blame.
</details>

## Redes

<details>
<summary><strong>12. Explique o three-way handshake do TCP.</strong></summary>
<br>

1. **SYN**: O cliente envia um pacote SYN ao servidor com um número de sequência inicial.
2. **SYN-ACK**: O servidor responde com SYN-ACK, confirmando o SYN do cliente e enviando seu próprio número de sequência.
3. **ACK**: O cliente envia um ACK confirmando o número de sequência do servidor. A conexão está estabelecida.

O encerramento usa um handshake de quatro vias: FIN → ACK → FIN → ACK (cada lado fecha independentemente sua metade da conexão).

Depuração com: `ss -tuln` (portas em escuta), `ss -tulnp` (com nomes de processos), `tcpdump -i eth0 port 80` (captura de pacotes).
</details>

<details>
<summary><strong>13. Qual é a diferença entre TCP e UDP?</strong></summary>
<br>

- **TCP** (Transmission Control Protocol): Orientado a conexão, confiável, entrega ordenada. Usa handshake, confirmações, retransmissões. Maior overhead. Usado para HTTP, SSH, FTP, bancos de dados.
- **UDP** (User Datagram Protocol): Sem conexão, não confiável, sem ordem garantida. Sem handshake, sem confirmações. Menor overhead, menor latência. Usado para DNS, DHCP, VoIP, streaming, gaming.

Ponto chave: "Não confiável" não significa ruim — significa que a aplicação lida com a confiabilidade se necessário. DNS usa UDP porque as consultas são pequenas e rápidas; se uma resposta é perdida, o cliente simplesmente reenvia.
</details>

<details>
<summary><strong>14. Um servidor não consegue alcançar um IP externo. Como você faz a resolução de problemas?</strong></summary>
<br>

Abordagem camada por camada:
1. **L1 - Físico**: `ip link show` — a interface está ativa?
2. **L2 - Enlace de Dados**: `ip neighbor show` — a tabela ARP está populada?
3. **L3 - Rede**: `ip route show` — existe um gateway padrão? `ping <gateway>` — você consegue alcançá-lo?
4. **L3 - Externo**: `ping 8.8.8.8` — você consegue alcançar a internet por IP?
5. **L7 - DNS**: `nslookup google.com` — a resolução DNS está funcionando? Verifique `/etc/resolv.conf`.
6. **Firewall**: `iptables -L -n` ou `nft list ruleset` — as conexões de saída estão bloqueadas?
7. **Rastreamento de rota**: `traceroute 8.8.8.8` — onde o caminho se interrompe?
</details>

## Armazenamento e Sistemas de Arquivos

<details>
<summary><strong>15. O que é um inode?</strong></summary>
<br>

Um inode é uma estrutura de dados que armazena metadados sobre um arquivo: permissões, propriedade, tamanho, timestamps e ponteiros para os blocos de dados no disco. Todo arquivo e diretório tem um inode.

Crucialmente, o **nome do arquivo NÃO é armazenado no inode** — é armazenado na entrada do diretório, que mapeia um nome para um número de inode. É por isso que hard links funcionam: múltiplas entradas de diretório podem apontar para o mesmo inode.

Ficar sem inodes (mesmo com espaço livre no disco) impede a criação de novos arquivos. Verifique com `df -i`. Causa comum: milhões de arquivos pequenos (filas de e-mail, diretórios de cache).
</details>

<details>
<summary><strong>16. Como você estende um volume lógico LVM sem tempo de inatividade?</strong></summary>
<br>

1. Verificar espaço disponível: `vgdisplay` — procurar PE (physical extents) livres.
2. Se não houver espaço livre, adicionar um novo disco físico: `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. Estender o volume lógico: `lvextend -L +10G /dev/myvg/mylv`.
4. Redimensionar o sistema de arquivos (online para ext4/XFS):
   - ext4: `resize2fs /dev/myvg/mylv`
   - XFS: `xfs_growfs /mountpoint`

Sem necessidade de desmontar. Sem tempo de inatividade. Esta é uma das principais vantagens do LVM sobre partições brutas.
</details>

## Segurança e Hardening

<details>
<summary><strong>17. Qual é a diferença entre su, sudo e sudoers?</strong></summary>
<br>

- **su** (switch user): Muda completamente para outro usuário. `su -` carrega o ambiente do usuário de destino. Requer a senha do usuário de destino.
- **sudo** (superuser do): Executa um único comando como outro usuário (geralmente root). Requer a senha do **chamador**. Fornece registro de auditoria de quem executou o quê.
- **sudoers** (`/etc/sudoers`): Arquivo de configuração que define quem pode usar sudo e quais comandos podem executar. Editado com segurança com `visudo` (validação de sintaxe).

Melhor prática: Desabilitar login direto como root (`PermitRootLogin no` no sshd_config). Dar acesso sudo aos administradores — fornece responsabilidade (registra quem fez o quê) e controle granular.
</details>

<details>
<summary><strong>18. Como você faz o hardening de um servidor SSH?</strong></summary>
<br>

Alterações essenciais no `/etc/ssh/sshd_config`:
- `PermitRootLogin no` — prevenir login direto como root.
- `PasswordAuthentication no` — forçar autenticação baseada em chave.
- `PubkeyAuthentication yes` — habilitar chaves SSH.
- `Port 2222` — mudar da porta padrão (reduz varreduras automatizadas).
- `MaxAuthTries 3` — limitar tentativas de autenticação.
- `AllowUsers deploy admin` — lista branca de usuários específicos.
- `ClientAliveInterval 300` — desconectar sessões ociosas.
- Instalar `fail2ban` — banir automaticamente IPs após tentativas de login falhas.
</details>

## Scripting e Automação

<details>
<summary><strong>19. Qual é a diferença entre $?, $$, $! e $@ no Bash?</strong></summary>
<br>

- **$?** — Status de saída do último comando (0 = sucesso, diferente de zero = falha).
- **$$** — PID do shell atual.
- **$!** — PID do último processo em segundo plano.
- **$@** — Todos os argumentos passados ao script (cada um como uma palavra separada).
- **$#** — Número de argumentos.
- **$0** — Nome do próprio script.
- **$1, $2, ...** — Argumentos posicionais individuais.

Padrão comum: `command && echo "success" || echo "fail"` usa `$?` implicitamente.
</details>

<details>
<summary><strong>20. Escreva um one-liner para encontrar todos os arquivos maiores que 100MB modificados nos últimos 7 dias.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

Detalhamento:
- `find /` — busca a partir da raiz.
- `-type f` — apenas arquivos (não diretórios).
- `-size +100M` — maiores que 100 megabytes.
- `-mtime -7` — modificados nos últimos 7 dias.
- `-exec ls -lh {} \;` — mostra o tamanho em formato legível para cada resultado.
- `2>/dev/null` — suprime erros de permissão negada.

Alternativa com ordenação: `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
