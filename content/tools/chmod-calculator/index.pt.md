---
title: "Calculadora Chmod: Permissões Linux"
description: "Ative leitura, escrita e execução para dono, grupo e outros e veja o número chmod (755, 644…), a string rwx e o comando pronto para copiar e colar."
intro: "Clique nos interruptores de permissão e veja o número **chmod**, a string `rwxr-xr-x` que aparece no `ls -l` e um comando pronto para rodar. Os atalhos cobrem os casos comuns: 755, 644, 600, 444 e o que deve ser evitado, 777."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["calculadora chmod", "chmod 755", "permissões de arquivos linux", "chmod 644", "permissões octais", "permissões rwx", "permissões unix", "gerador de comando chmod"]
tags: ["linux", "sysadmin", "permissões", "ferramenta"]
app_category: "DeveloperApplication"
tool_partial: "chmod-calculator"
howto:
  - "Para cada classe (**Dono**, **Grupo**, **Outros**) ligue ou desligue **Leitura**, **Escrita** e **Execução**. O padrão é 755."
  - "Leia o número octal depois de `chmod` e a string simbólica abaixo, a mesma notação que o `ls -l` mostra."
  - "Digite o nome do arquivo: nomes com espaços ou caracteres especiais do shell são colocados entre aspas automaticamente no comando copiado."
  - "Ou comece por um **atalho**: 755 para scripts e pastas, 644 para arquivos comuns, 600 para chaves privadas, 444 para arquivos somente leitura."
  - "Clique em **Copiar comando** e cole no terminal."
faq:
  - q: "O que significa chmod 755?"
    a: "7 para o dono (leitura 4 + escrita 2 + execução 1), 5 para o grupo (leitura 4 + execução 1) e 5 para os outros. O dono pode tudo; os demais podem ler e executar, mas não alterar. É o padrão para scripts, binários e pastas."
  - q: "Qual a diferença entre 644 e 755?"
    a: "644 (`rw-r--r--`) não tem o bit de execução: serve para documentos, configurações e arquivos web. 755 (`rwxr-xr-x`) acrescenta execução para todos: necessário para scripts e programas, e para pastas, onde \"executar\" significa poder entrar nelas."
  - q: "Por que chmod 777 é perigoso?"
    a: "Ele deixa qualquer usuário do sistema alterar o arquivo ou a pasta. Em um servidor compartilhado ou na raiz de um site, qualquer processo comprometido pode substituir seu código ou plantar arquivos. Se algo só funciona com 777, a solução real costuma ser o dono ou o grupo do arquivo (`chown`), e não permissões mais abertas."
  - q: "Quais permissões uma chave privada SSH deve ter?"
    a: "600 (`rw-------`): leitura e escrita só para você. O OpenSSH se recusa a usar uma chave privada que outros possam ler e mostra \"UNPROTECTED PRIVATE KEY FILE\". A pasta `~/.ssh` deve ser 700."
  - q: "O que significa execução em uma pasta?"
    a: "É a permissão para atravessá-la: entrar com `cd` e acessar os arquivos de dentro pelo nome. A leitura numa pasta permite listar os nomes; sem execução você vê os nomes, mas não abre os arquivos. Por isso as pastas costumam ser 755 ou 700."
  - q: "Ela suporta setuid, setgid ou o sticky bit?"
    a: "Não. A calculadora cobre os nove bits básicos, o modo de três dígitos usado em quase todos os comandos `chmod`. Os bits especiais são um quarto dígito na frente (4 setuid, 2 setgid, 1 sticky, como em `chmod 1777 /tmp`); acrescente à mão se precisar."
---

## Como funciona

As permissões Unix são nove bits em três grupos de três. Cada grupo responde às mesmas três perguntas, leitura, escrita, execução, para uma classe de usuários: o **dono** do arquivo (`u`), o **grupo** dele (`g`) e todos os **outros** (`o`).

Cada permissão tem um valor fixo, e um dígito é simplesmente a soma deles:

| Permissão | Valor | Símbolo |
|---|---|---|
| Leitura | 4 | `r` |
| Escrita | 2 | `w` |
| Execução | 1 | `x` |

Então 7 = 4 + 2 + 1 = `rwx`, 6 = 4 + 2 = `rw-`, 5 = 4 + 1 = `r-x` e 4 = `r--`. A calculadora soma os interruptores ligados de cada classe, escreve os três dígitos lado a lado e converte cada dígito de volta em `r`, `w`, `x` ou `-` com um teste de bits (`dígito & 4`, `& 2`, `& 1`). O `-` no início da string simbólica é o caractere de tipo que o `ls -l` mostra para um arquivo comum (`d` para uma pasta).

Os atalhos fazem o contrário: cada dígito de `644` é decomposto em bits para ajustar os nove interruptores.

O comando copiado é `chmod <octal> <arquivo>`. Se o nome tiver algo além de letras, números e `._/@%+=:,-`, ele é colocado entre aspas simples (`'meu arquivo.sh'`), com as aspas internas escapadas no padrão POSIX, para que o comando possa ser colado com segurança no bash ou no zsh.

### Modos comuns

| Modo | Simbólico | Uso típico |
|---|---|---|
| 755 | `rwxr-xr-x` | Scripts, binários, pastas |
| 644 | `rw-r--r--` | Arquivos comuns, configurações, arquivos web |
| 700 | `rwx------` | Pastas privadas como `~/.ssh` |
| 600 | `rw-------` | Chaves privadas, arquivos `.env`, credenciais |
| 444 | `r--r--r--` | Arquivos que ninguém deve alterar |
| 777 | `rwxrwxrwx` | Quase nunca: qualquer um pode alterar |

## Casos de uso

- **"Permission denied" ao rodar um script.** Acrescente o bit de execução: `chmod 755 deploy.sh`, ou `chmod u+x` se só você vai rodar.
- **Proteger segredos.** Deixe arquivos `.env`, arquivos com chaves de API e chaves SSH em 600 para que outros usuários da máquina não consigam ler.
- **Servidores web.** As configurações típicas usam 644 para arquivos e 755 para pastas, com dono no usuário de deploy e leitura liberada para o servidor web.
- **Docker e CI.** Arquivos copiados para imagens ou baixados pela CI às vezes perdem o bit de execução; a calculadora entrega a linha `RUN chmod` exata.
- **Aprender a notação.** Converta entre a saída do `ls -l` e os números octais até ler `drwxr-x---` de cara.
