---
title: "Calculateur Chmod : Droits Linux"
description: "Activez lecture, écriture et exécution pour propriétaire, groupe et autres et obtenez le nombre chmod (755, 644…), la chaîne rwx et la commande à copier."
intro: "Cliquez sur les interrupteurs de droits et obtenez le nombre **chmod**, la chaîne `rwxr-xr-x` affichée par `ls -l` et une commande prête à lancer. Les préréglages couvrent les cas courants : 755, 644, 600, 444, et celui à éviter, 777."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["calculateur chmod", "chmod 755", "droits fichiers linux", "chmod 644", "permissions octales", "permissions rwx", "droits unix", "générateur commande chmod"]
tags: ["linux", "sysadmin", "permissions", "outil"]
app_category: "DeveloperApplication"
tool_partial: "chmod-calculator"
howto:
  - "Pour chaque classe (**Propriétaire**, **Groupe**, **Autres**), activez ou désactivez **Lecture**, **Écriture** et **Exécution**. La valeur par défaut est 755."
  - "Lisez le nombre octal après `chmod` et la chaîne symbolique dessous, la même notation que celle affichée par `ls -l`."
  - "Saisissez le nom du fichier : les noms contenant des espaces ou des caractères spéciaux du shell sont automatiquement mis entre guillemets dans la commande copiée."
  - "Ou partez d'un **préréglage** : 755 pour les scripts et dossiers, 644 pour les fichiers ordinaires, 600 pour les clés privées, 444 pour les fichiers en lecture seule."
  - "Cliquez sur **Copier la commande** et collez-la dans votre terminal."
faq:
  - q: "Que signifie chmod 755 ?"
    a: "7 pour le propriétaire (lecture 4 + écriture 2 + exécution 1), 5 pour le groupe (lecture 4 + exécution 1) et 5 pour les autres. Le propriétaire peut tout faire ; les autres peuvent lire et exécuter, mais pas modifier. C'est la norme pour les scripts, les binaires et les dossiers."
  - q: "Quelle différence entre 644 et 755 ?"
    a: "644 (`rw-r--r--`) n'a pas de bit d'exécution : adapté aux documents, configurations et fichiers web. 755 (`rwxr-xr-x`) ajoute l'exécution pour tous : nécessaire pour les scripts et programmes, et pour les dossiers, où « exécuter » signifie pouvoir y entrer."
  - q: "Pourquoi chmod 777 est-il dangereux ?"
    a: "Il permet à tout utilisateur du système de modifier le fichier ou le dossier. Sur un serveur partagé ou à la racine d'un site, n'importe quel processus compromis peut alors remplacer votre code ou déposer des fichiers. Si quelque chose ne marche qu'en 777, la vraie solution est généralement le propriétaire ou le groupe du fichier (`chown`), pas des droits plus larges."
  - q: "Quels droits pour une clé privée SSH ?"
    a: "600 (`rw-------`) : lisible et modifiable par vous seul. OpenSSH refuse une clé privée lisible par d'autres et affiche « UNPROTECTED PRIVATE KEY FILE ». Le dossier `~/.ssh` lui-même devrait être en 700."
  - q: "Que signifie l'exécution sur un dossier ?"
    a: "C'est le droit de le traverser : y entrer avec `cd` et accéder par leur nom aux fichiers qu'il contient. La lecture sur un dossier permet d'en lister les noms ; sans exécution, vous voyez les noms mais ne pouvez pas ouvrir les fichiers. C'est pourquoi les dossiers sont généralement en 755 ou 700."
  - q: "Gère-t-il setuid, setgid ou le sticky bit ?"
    a: "Non. Le calculateur couvre les neuf bits de base, le mode à trois chiffres utilisé dans presque toutes les commandes `chmod`. Les bits spéciaux forment un quatrième chiffre en tête (4 setuid, 2 setgid, 1 sticky, comme dans `chmod 1777 /tmp`) ; ajoutez-le à la main si besoin."
---

## Comment ça marche

Les droits Unix sont neuf bits répartis en trois groupes de trois. Chaque groupe répond aux trois mêmes questions, lecture, écriture, exécution, pour une classe d'utilisateurs : le **propriétaire** du fichier (`u`), son **groupe** (`g`) et tous les **autres** (`o`).

Chaque droit a une valeur fixe, et un chiffre est simplement leur somme :

| Droit | Valeur | Symbole |
|---|---|---|
| Lecture | 4 | `r` |
| Écriture | 2 | `w` |
| Exécution | 1 | `x` |

Ainsi 7 = 4 + 2 + 1 = `rwx`, 6 = 4 + 2 = `rw-`, 5 = 4 + 1 = `r-x` et 4 = `r--`. Le calculateur additionne les interrupteurs actifs de chaque classe, écrit les trois chiffres côte à côte puis reconvertit chaque chiffre en `r`, `w`, `x` ou `-` par un test de bits (`chiffre & 4`, `& 2`, `& 1`). Le `-` initial de la chaîne symbolique est le caractère de type que `ls -l` affiche pour un fichier ordinaire (`d` pour un dossier).

Les préréglages font l'inverse : chaque chiffre de `644` est décomposé en bits pour positionner les neuf interrupteurs.

La commande copiée est `chmod <octal> <fichier>`. Si le nom contient autre chose que des lettres, chiffres et `._/@%+=:,-`, il est entouré de guillemets simples (`'mon fichier.sh'`), les apostrophes internes étant échappées à la manière POSIX : la commande peut être collée sans risque dans bash ou zsh.

### Modes courants

| Mode | Symbolique | Usage typique |
|---|---|---|
| 755 | `rwxr-xr-x` | Scripts, binaires, dossiers |
| 644 | `rw-r--r--` | Fichiers ordinaires, configurations, ressources web |
| 700 | `rwx------` | Dossiers privés comme `~/.ssh` |
| 600 | `rw-------` | Clés privées, fichiers `.env`, identifiants |
| 444 | `r--r--r--` | Fichiers que personne ne doit modifier |
| 777 | `rwxrwxrwx` | Presque jamais : tout le monde peut le modifier |

## Cas d'usage

- **« Permission denied » en lançant un script.** Ajoutez le bit d'exécution : `chmod 755 deploy.sh`, ou `chmod u+x` si vous êtes le seul à l'exécuter.
- **Protéger les secrets.** Passez en 600 les fichiers `.env`, les fichiers de clés d'API et les clés SSH pour que les autres utilisateurs de la machine ne puissent pas les lire.
- **Serveurs web.** Les configurations classiques utilisent 644 pour les fichiers et 755 pour les dossiers, appartenant à l'utilisateur de déploiement et lisibles par le serveur web.
- **Docker et CI.** Les fichiers copiés dans une image ou récupérés par la CI perdent parfois leur bit d'exécution ; le calculateur vous donne la ligne `RUN chmod` exacte.
- **Apprendre la notation.** Passez de la sortie de `ls -l` aux nombres octaux jusqu'à lire `drwxr-x---` d'un coup d'œil.
