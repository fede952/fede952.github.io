---
title: "Quelle est mon IP ? Test de Confidentialité"
description: "Affichez votre IP publique, FAI et position, vérifiez l'exposition de l'IP locale via WebRTC, le GPU et l'empreinte de l'appareil, avec un score."
intro: "**NetGuard** montre ce que n'importe quel site apprend sur vous dès que vous vous connectez : votre adresse IP publique, votre fournisseur d'accès et votre position approximative, plus les signaux de l'appareil que votre navigateur livre gratuitement. Un clic, un score de confidentialité et des explications claires."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["quelle est mon ip", "mon adresse ip", "test fuite ip", "test fuite webrtc", "test confidentialité navigateur", "vérifier mon vpn", "ce que les sites savent de moi", "score de confidentialité"]
tags: ["vie privée", "réseau", "vpn", "outil"]
app_category: "SecurityApplication"
tool_file: "/tools/netguard/"
tool_title: "NetGuard : test de confidentialité du navigateur et de fuite d'IP"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
howto:
  - "Cliquez sur **Run Privacy Scan**. L'analyse dure environ quatre secondes, essentiellement pour le contrôle WebRTC."
  - "Lisez **Network & Location** : l'adresse IP publique, le fournisseur et la ville que voit chaque serveur web quand vous vous connectez, obtenus via ipwho.is."
  - "Regardez la carte **WebRTC**. En vert, le navigateur n'a exposé aucune adresse réseau privée ; en rouge, la liste des adresses divulguées."
  - "Parcourez les cartes d'empreinte (système, navigateur, écran, GPU, langue et fuseau horaire, batterie) : n'importe quel site peut les lire sans demander d'autorisation."
  - "Comparez le **Privacy Score** avant et après un changement, par exemple en activant un VPN, en changeant de navigateur ou en bloquant WebGL, puis cliquez sur **Scan Again**."
faq:
  - q: "Quelle est mon adresse IP et qui peut la voir ?"
    a: "Votre IP publique est l'adresse que votre fournisseur d'accès (ou votre VPN) attribue à votre connexion. Tous les sites, serveurs publicitaires et CDN que vous contactez la voient, car elle sert à vous renvoyer la page. Elle révèle généralement votre fournisseur et votre ville ou région, rarement votre rue exacte."
  - q: "Un VPN masque-t-il mon IP dans ce test ?"
    a: "Oui : les cartes IP, fournisseur et position affichent alors les informations du serveur VPN au lieu des vôtres, ce qui est le but d'un VPN. Le score, lui, ne sait pas si une adresse appartient à un VPN et retire les mêmes points pour toute IP visible : comparez les cartes, pas seulement le chiffre."
  - q: "Qu'est-ce qu'une fuite WebRTC ?"
    a: "WebRTC permet aux navigateurs d'établir des connexions pair à pair pour les appels vidéo. Pour cela, il rassemble des « candidats ICE », les adresses réseau où votre appareil est joignable. Les anciens navigateurs exposaient ainsi à n'importe quelle page l'adresse LAN privée de l'appareil (comme 192.168.1.23). NetGuard vérifie précisément cela ; les navigateurs modernes la masquent désormais derrière un nom aléatoire en `.local`."
  - q: "NetGuard peut-il dire si mon VPN laisse fuiter ma vraie IP via WebRTC ?"
    a: "Pas complètement. Le contrôle s'exécute sans serveur STUN : il révèle les adresses du réseau local mais ne demande pas à un serveur extérieur à quoi ressemble votre adresse publique via WebRTC. Pour tester cette fuite VPN précise, activez le VPN, ouvrez un test WebRTC dédié basé sur STUN et comparez l'adresse publique qu'il indique avec l'IP affichée ici."
  - q: "Pourquoi le modèle de mon GPU est-il visible ?"
    a: "Via l'extension WebGL `WEBGL_debug_renderer_info`, une page peut lire la chaîne exacte du moteur de rendu graphique, par exemple un modèle de GPU NVIDIA ou Apple. Combinée à la taille d'écran, au fuseau horaire et à la langue, elle vous range dans un petit groupe d'appareils. Certains navigateurs renvoient une valeur générique ou la bloquent, ce que NetGuard signale comme sûr."
  - q: "L'outil enregistre-t-il ou envoie-t-il mes données ?"
    a: "Une seule requête quitte votre navigateur : l'appel à ipwho.is qui renvoie votre IP publique et sa localisation, une requête que n'importe quel site visité pourrait faire. Tout le reste est lu et affiché localement, et rien n'est conservé à la fermeture de la page."
---

## Comment ça marche

L'analyse enchaîne cinq contrôles, tous dans la page, puis les transforme en score.

**1. Identité réseau.** Le navigateur appelle `https://ipwho.is/`, une API publique de géolocalisation IP. La réponse contient l'adresse d'où est partie la requête, le fournisseur ou l'organisation qui la détient, ainsi que le pays, la ville et les coordonnées approximatives de cette adresse. Ce sont les mêmes informations que n'importe quel serveur web tire de votre connexion, d'où l'avertissement sur la carte.

**2. Qualité de connexion.** Là où existe la **Network Information API** (navigateurs basés sur Chromium), `navigator.connection` indique le débit estimé en Mbit/s, un type de connexion effectif comme `4g` et le temps aller-retour. Firefox et Safari ne l'exposent pas, et la carte le précise.

**3. Empreinte de l'appareil.** NetGuard lit les signaux que les scripts de fingerprinting collectent le plus souvent :

- système d'exploitation et version du navigateur tirés de la chaîne `User-Agent`, plus `navigator.platform` ;
- résolution d'écran, ratio de pixels, taille de la fenêtre et profondeur de couleur ;
- le **moteur de rendu et le fabricant du GPU**, depuis un contexte WebGL via l'extension `WEBGL_debug_renderer_info` ;
- `navigator.language` et le fuseau horaire d'`Intl.DateTimeFormat().resolvedOptions()` ;
- niveau et état de charge de la batterie avec `navigator.getBattery()`, quand le navigateur le propose encore.

**4. Contrôle des adresses locales via WebRTC.** La page crée une `RTCPeerConnection` sans serveur ICE, ouvre un canal de données et génère une offre. Le navigateur émet alors des candidats ICE de type *host*, chacun contenant une adresse réseau. NetGuard collecte les adresses IPv4 en ignorant les noms mDNS se terminant par `.local`, que les navigateurs modernes utilisent pour masquer la vraie adresse LAN. Chaque adresse collectée est listée comme exposée. Au bout de quatre secondes, le contrôle s'arrête.

**5. Score de confidentialité.** Le score part de 100 et perd des points pour chaque exposition trouvée :

| Signal | Points |
|---|---|
| IP publique et position consultables | −30 |
| IP privée exposée via WebRTC | −20 |
| Système, navigateur et écran lisibles | −10 |
| Modèle exact du GPU lisible | −10 |
| Langue et fuseau horaire lisibles | −5 |
| État de la batterie lisible | −5 |

Chrome sur ordinateur obtient généralement 40 (exactement ce score lors de notre test) ; les navigateurs qui masquent la chaîne du GPU ou n'implémentent pas la Battery API gagnent 5 à 15 points. Le chiffre sert à amorcer la réflexion, ce n'est pas une mesure de laboratoire : ce sont les cartes qui comptent.

## Cas d'usage

- **Vérifier que votre VPN est actif.** Connectez-le et lancez l'analyse : l'IP, le fournisseur et la ville doivent être ceux du VPN, pas de votre connexion à la maison.
- **Voir ce qu'un site apprend avant de vous inscrire.** Les cartes correspondent exactement à ce qu'un script d'analyse ou de publicité peut lire dès la première page.
- **Comparer les navigateurs.** Lancez l'analyse dans Chrome, Firefox, Brave et Safari : les cartes GPU, batterie et connexion varient beaucoup.
- **Comprendre un blocage géographique.** Si une plateforme de streaming vous croit dans le mauvais pays, la carte de position montre dans quel pays votre IP semble se trouver.
- **Expliquer les bases.** Une démo de deux minutes avec NetGuard explique les adresses IP, le fingerprinting et WebRTC mieux qu'un diaporama. Pour une analyse plus poussée de l'empreinte, essayez GhostPrint.
