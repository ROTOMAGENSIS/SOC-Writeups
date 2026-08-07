# BEC-KY — Investigation d’un Business Email Compromise dans Microsoft 365

> Blue Team Labs Online | BEC | Phishing | Microsoft 365 | Azure Audit Logs

## Résumé exécutif

L’organisation soupçonne un incident impliquant des **virements bancaires non autorisés**, mais apparemment légitimes, depuis le fonds de pension de l'entreprise vers de multiples comptes externes. Le compte du **Chief Financial Officer** constitue une cible sensible car il dispose de l’autorité nécessaire pour autoriser ces transactions.

L’investigation a permis d’identifier une attaque de type **Business Email Compromise**, ou **BEC**. L’incident a débuté par la réception d’un courriel de **phishing** contenant un lien vers un faux portail d’authentification Microsoft.

Il provenait de l’adresse **légitime** : **sabastian@flanaganspensions[.]co[.]uk**

Le lien malveillant redirige vers un domaine utilisé pour imiter le portail de connexion légitime : `hxxps[://]login[.]portal[.]microsoft[.]copilotweb[.]co/GuKdDmBu`

Le courriel est daté du **2 juillet 2025, à 15:40**. Les éléments recueillis indiquent que les identifiants du CFO ont été compromis puis utilisés pour accéder à son compte.

**Deux adresses IP** sont associées à l’acteur malveillant :

- `159.203.17[.]81`

- `95.181.232[.]30`

Suite à la compromission, l’attaquant effectué deux opérations pour dissimuler son activité :

- La première est une règle de boîte de réception recherchant le mot **Withdrawal** dans le sujet ou le corps des messages avant de les supprimer.

- La deuxième est la création d’un dossier **History** utilisé pour déplacer certains courriels afin de les dissimuler au propriétaire légitime.

L’analyse d’un courriel d’une transaction a permis d’identifier la banque destinataire comme étant **First Bank of Nigeria** **LTD**.

La chaîne d’attaque observée est la suivante :

1.  Phishing

2.  Vol des identifiants via le faux portail

3.  Prise de contrôle du compte du CFO

4.  Accès à la messagerie

5.  Création des règles de dissimulation

6.  Interception/Suppression des alertes financières

7.  Fraude par virement bancaire

La compromission est de niveau **critique** en raison du niveau d’autorité du compte compromis, de l’action sur les boîtes de réception et de l’impact financier direct.

## Contexte et périmètre

Au cours d’une période d’environ 48 heures, l’organisation a constaté qu’un nombre important de virements avait été traité depuis son fonds de pension. Les fonds avaient été transférés vers plusieurs comptes bancaires externes, dont certains situés à l’étranger.

Les transactions semblaient avoir été correctement autorisées. L’organisation a donc envisagé la compromission d’un utilisateur possédant les droits nécessaires pour approuver les paiements, en particulier le CFO.

L’**hypothèse principale** est donc :

Un acteur malveillant a compromis le compte Microsoft 365 du CFO, puis a utilisé son identité et son accès à la messagerie pour faciliter ou dissimuler des opérations financières frauduleuses.

## Sources de données disponibles

Pour mener cette investigation, nous disposons de **quatre courriels** et d’un **journal d’activité Azure.**

- Un courriel de phishing : (No subject.eml)

- Deux courriels internes : Re_PensionApproval.eml et Re_20250701-Pension Fund Withdrawals.eml

- Un courriel frauduleux provenant du CFO compromis : 20250702-Withdrawal-Bernard.eml

Le journal d’activité Azure contient les informations détaillées en format JSON comme : utilisateur concerné, opération réalisée, horodatage, adresses IP, identifiants, règles et paramètres de messagerie, objets Exchange.

Quelques opérations sont particulièrement importantes pour cette investigation :

- UserLoggedIn : identifier une authentification réussie

- UserLoginFailed : identifier une authentification échouée

- MailItemsAccessed : détecter un accès à des messages

- New-InboxRule : identifier la création de règle de boîte

- Send : identifier l’envoi d’un message

- New-MailboxFolder : identifier la création d’un dossier Exchange

## Méthodologie d’investigation

Le courriel initial, reçu le **mercredi 2 juillet 2025, à 15:40:37** +000, permet d’identifier l’adresse source, la date d’envoi, les liens contenus dans le message, les vrais domaines utilisés et des signes d’usurpation. L’url observé, `hxxps[://]login[.]portal[.]microsoft[.]copilotweb[.]co/GuKdDmBu`, nous indique un domaine réel est **`copilotweb[.]co`.** Les autres termes (login, portal, microsoft) servent à tromper l’utilisateur. Un portail légitime utiliserait un domaine contrôlé par Microsoft, et non un sous-domaine de `copilotweb[.]co`.

Ensuite, nous devons tout d’abord détecter et qualifier la compromission. L’accès non autorisé au compte correspond à un **Account Takeover**. Mais comme l’objectif final de l’attaquant était la réalisation et la dissimulation d’une opération financière frauduleuse par l’intermédiaire d’un compte de messagerie professionnel, l’incident est un **Business Email Compromise**.

**ATO** est la compromission technique du compte alors que **BEC** est l’opération de fraude dans son ensemble.

### Identification des adresses IP malveillantes

Nous avons utilisé les évènements `UserLoggedIn` et `UserLoginFailed` pour détecter les adresses IP, en se concentrant sur le compte de **Becky** (**becky.lorray@tempestasenergy[.]com**) pour filtrer les données.

Méthode : Comme le courriel est reçu à **15:40:37**, nous cherchons un événement `UserLoggedIn` postérieur à cette date, ce qui supposerait que l’attaquant a probablement reçu les identifiant de **Becky** via son faux portail et qu’il s’est connecté à son compte. On observe alors l’adresse `159.203.17[.]81` (paramètres : ClientIP, ClientIPAdress et ActorIPAddress) associée à l’évènement UserLoggedIn à **15:41:57** et **15:42:07.**

On observe également un événement `UserLoginFailed` associé à cette adresse IP à **15:25:14**. Nous supposons alors que l’attaquant a essayé de se connecter au compte de **Liam** (liam.fray@tempestasenergy[.]com) avant de se connecter à celui de Becky.

La deuxième adresse malveillante, **`95.181.232[.]30`,** est détectable, dans un premier temps, via l’événement `UserLoggedIn` associé à Becky, à 15:45:05,09,10 et 15:49:39. Dans un second temps, elle est corroborée par les événements `New-InboxRule` à 15:48:39 et 15:58:42 qui attestent que l’attaquant a manipulé les règles de messageries de **Becky**.

Nous avons utilisé l’interface de **Notepad++** mais il est tout à fait possible d’utiliser l’outil **grep** via WSL pour rechercher et isoler certains termes, surtout lorsque le journal d’activité est volumineux.

Par exemple :

```bash
grep -E 'UserLoggedIn|UserLoginFailed' azure-export-audit-dfir.csv \
  | grep -oE '"ClientIP":"[^"]*"' \
  | sort -u
```

**Environnement réel** : Avec les informations de l’entreprise, on peut établir une baseline et ainsi détecter plus rapidement les adresses IP inconnues et opérations anormales.

Une recherche d'enrichissement des adresses IP permet d'associer `95.181.232[.]30` au Maroc et `159.203.17[.]81` aux États-Unis. Ces informations constituent un élément contextuel et ne permettent pas de déterminer la localisation réelle de l'attaquant, notamment en raison de l'utilisation possible de VPN, proxys ou infrastructures hébergées.

### Analyse des règles de boite

Nous avons filtré les événements `New-InboxRule` pour identifier les règles créées pendant la compromission. En filtrant dans le journal d’activité, on observe deux événements.

1.  Le premier événement, à 15:48:39, montre une règle supprimant les messages qui ont pour sujet ou corps (SubjectOrBodyContainsWords) le mot **Withdrawal** envoyé par (From) **Sabastian** (`sabastian@flanaganspensions[.]co[.]uk`).

2.  Le deuxième événement, à 15:58:42, montre une règle déplaçant les messages envoyés (SentTo) à **Sabastian** dans le dossier (MoveToFolder) **History**.

### Hypothèse de compromission

**Becky** est la CFO de **Tempestas Energy**. En tant que tel, tout retrait depuis le fond de pension requiert son approbation directe (comme mentionné dans le courriel Re 20250701-Pension Fund Withdrawals). **Sabastian** est le Directeur de **Flanagans Pensions**. Les deux se sont mis d’accord par téléphone (le 2 juillet à 12:54) sur un processus formel pour l’approbation d’une demande de retrait comme le confirme le courriel **PensionApproval**.

L’analyse des **en-têtes** du courriel de phishing montre que **SPF** et **DMARC** ont réussi pour le domaine `flanaganspensions[.]co[.]uk`. Cela nous pousse à supposer que le compte de Sabastian **avait déjà été compromis**. L’attaquant l’a ensuite utilisé comme compte de confiance pour envoyer le **spearphishing** à Becky. Cette hypothèse est plausible car cela **expliquerait pourquoi l’attaquant a ciblé Becky**, mais aussi Liam, qui était en copie du courriel **PensionApproval** (et que l’on a retrouvé dans l’événement UserLoginFailed).

En compromettant le compte de **Becky**, l’attaquant crée une règle pour supprimer les messages provenant de Sabastian et qui contiennent “**Withdrawal**”. Cette règle permet à l’attaquant de contrôler les flux de communications et empêche Becky de voir les confirmations, demandes de vérification ou alertes relatives aux retraits frauduleux envoyés depuis son propre compte.

A noter : Il ne supprime pas tous les messages de Sabastian, rendant la règle plus discrète.

Cela explique pourquoi l’adresse de Sabastian apparaît à la fois :

- comme source du phishing ;

- comme expéditeur ciblé par la règle de suppression ;

- comme destinataire de la fausse demande de retrait envoyée depuis Becky.

### Corrélation avec le courriel financier

Le courriel **20250702-Withdrawal-Bernard** du 2 juillet 2025 à **15:57:23** contient les informations relatives à une transaction. Cet artéfact nous permet d’identifier la banque destinataire comme étant **First Bank of Nigeria LTD** grâce au SWIFT/BIC (FBNINGLA). D’autres artéfacts sont disponibles sur ce mail comme le nom de l’employé et son numéro de compte.

## Chronologie de l’attaque

Les horodatages des courriels, des authentifications et de la création des règles nous permettent d’établir une chronologie de l’attaque du mercredi 2 juillet 2025 avec un niveau de confiance élevé.

- **15:40:37** : Becky reçoit le courriel de phishing provenant de l’adresse de **Sabastian** (`sabastian@flanaganspensions[.]co[.]uk`)

- **Entre 15:40:37 et 15:41:57** : Les éléments portent à croire que Becky a renseigné ses identifiants dans le faux portail de connexion `copilotweb[.]co`.

- **15:41:57**, **15:42:07, 15:45:05, 15:49:39** : l’attaquant se connecte au compte de Becky avec l’adresse `159.203.17[.]81` et `95.181.232[.]30`.

- **15:48:39** : l’attaquant crée la première règle recherchant **Withdrawal**.

- **15:57:23** : Courriel financier frauduleux **20250702-Withdrawal-Bernard**

- **15:58:42** : l’attaquant crée la seconde règle de déplacement de messages envoyé à **Sabastian** vers le dossier **History**.

## Analyse technique

La corrélation des différents artefacts permet de reconstituer une séquence cohérente entre le phishing initial, la compromission du compte de **Becky** et les actions de dissimulation réalisées dans sa boîte Microsoft 365.

Le courriel de phishing est reçu à 15:40:37 et contient un lien vers le faux portail Microsoft hébergé sur `copilotweb[.]co`. La première authentification suspecte sur le compte de Becky apparaît seulement 1 minute et 20 secondes plus tard, à 15:41:57, depuis `159.203.17[.]81`. Une seconde adresse, `95.181.232[.]30`, est ensuite observée à partir de 15:45:05.

Cette proximité temporelle constitue un faisceau d'indices fort en faveur d'une compromission du compte à la suite du phishing, même si les journaux disponibles ne permettent pas de prouver que Becky a saisi ses identifiants sur le faux portail.

À 15:48:39, une première règle `New-InboxRule` est créée depuis une session associée à `95.181.232[.]30`. Elle cible les messages provenant de Sabastian et contenant le terme Withdrawal dans leur sujet ou leur corps, puis les supprime. Cette action semble destinée à empêcher Becky de voir les réponses ou confirmations de Sabastian relatives aux retraits financiers.

À 15:57:23, le **compte compromis de Becky** est utilisé pour **envoyer une demande frauduleuse de retrait vers Sabastian**. Le message contient notamment les coordonnées bancaires permettant d'identifier **First Bank of Nigeria LTD** comme banque destinataire.

Enfin, à 15:58:42, une seconde règle est créée afin de déplacer vers le dossier **History** les messages correspondant aux critères définis par l'attaquant. Cette nouvelle manipulation renforce l'hypothèse d'une volonté de **contrôler les échanges visibles** par Becky et de dissimuler l'activité frauduleuse.

La séquence observée peut être résumée ainsi :

- 15:40:37 Réception du phishing

- 15:41:57 Première authentification suspecte

- 15:45:05 Utilisation de la seconde IP

- 15:48:39 Création de la règle "**Withdrawal**" → suppression

- 15:57:23 Envoi de la demande frauduleuse de retrait

- 15:58:42 Création de la règle de déplacement vers "History"

Cette corrélation entre courriels, authentifications et modifications de la boîte aux lettres permet d'établir avec un niveau de confiance élevé que le compte de Becky a été utilisé par un acteur tiers pour réaliser puis dissimuler une fraude financière.

## Indicateurs de compromission

| **Type**             | **Valeur défangée**                                                       | **Contexte**                                     |
|----------------------|---------------------------------------------------------------------------|--------------------------------------------------|
| Adresse d’expédition | sabastian@flanaganspensions[.]co[.]uk                                         | Expéditeur du phishing initial                   |
| URL                  | `hxxps[://]login[.]portal[.]microsoft[.]copilotweb[.]co/GuKdDmBu` | Lien de phishing                                 |
| Domaine              | `copilotweb[.]co`                                                         | Domaine contrôlant le faux portail               |
| Adresse IP           | `159.203.17[.]81`                                                         | Infrastructure utilisée pendant la compromission |
| Adresse IP           | `95.181.232[.]30` (Maroc)                                                 | Infrastructure utilisée pendant la compromission |
| Mot-clé de règle     | Withdrawal                                                                | Déclencheur de la première règle malveillante    |
| Dossier de boîte     | History                                                                   | Dossier utilisé pour masquer des courriels       |

### Indicateurs comportementaux

- authentification du CFO depuis une nouvelle adresse IP ;
- authentifications depuis plusieurs pays dans un court intervalle ;
- création soudaine de règles de boîte ;
- règle utilisant un vocabulaire financier ;
- suppression automatique de messages ;
- déplacement de messages vers un dossier inhabituel ;
- accès inhabituel aux courriels ;
- envoi de demandes de paiement depuis un compte de direction ;
- modification d’informations bancaires ;
- virement vers un nouveau bénéficiaire ;
- utilisation d’un compte cloud depuis une infrastructure d’hébergement ou de VPN.

## Mapping MITRE ATT&CK

| **Tactique**                                   | **Technique**                             | **Identifiant** | **Application au cas**                                                                  |
|------------------------------------------------|-------------------------------------------|-----------------|-----------------------------------------------------------------------------------------|
| Initial Access                                 | Phishing: Spearphishing Link              | T1566.002       | Le courriel initial contenait un lien vers un faux portail Microsoft                    |
| Credential Access                              | Input Capture: Web Portal Capture         | T1056.003       | Le faux portail semble avoir été utilisé pour collecter les identifiants de la victime  |
| Initial Access / Persistence / Defense Evasion | Valid Accounts: Cloud Accounts            | T1078.004       | Les identifiants du compte Microsoft 365 du CFO ont été utilisés pour accéder au tenant |
| Collection                                     | Email Collection: Remote Email Collection | T1114.002       | L’acteur a accédé à une boîte Exchange Online à l’aide du compte compromis              |
| Defense Evasion                                | Indicator Removal: Clear Mailbox Data     | T1070.008       | Une règle a été créée afin de supprimer les courriels correspondant au mot Withdrawal   |
| Impact                                         | Financial Theft                           | T1657           | L’objectif final était le détournement de fonds vers des comptes externes               |

## Évaluation de la criticité

Sévérité : **Critique**

Justification : compromission d’un compte CFO, création de règles de dissimulation et fraude financière avérée.

## Mesures de réponse recommandées

Afin de supprimer tout accès illégitime obtenu grâce à cette attaque, nous recommandons de :

- réinitialiser le mot de passe ;
- révoquer les sessions ;
- vérifier les méthodes MFA ;
- supprimer les Inbox Rules malveillantes ;
- examiner les forwarding rules et délégations ;
- rechercher les mêmes IOC dans le tenant ;
- identifier les autres comptes touchés ;
- bloquer domaine/IP si pertinent ;
- créer ou suggérer des détections sur New-InboxRule, connexions inhabituelles et MailItemsAccessed.

### Créer des alertes pour les scénarios suivants 

| **Type d'alerte**        | **Logique / Conditions**                                                        |
|--------------------------|---------------------------------------------------------------------------------|
| Suppression de messages  | New-InboxRule AND DeleteMessage = True                                          |
| Exfiltration par dossier | New-InboxRule AND MoveToFolder != empty AND Utilisateur in (Finance, Executive) |
| Mots-clés financiers     | New-InboxRule AND SubjectOrBodyContainsWords (vocabulaire financier)            |
| Compromission immédiate  | UserLoggedIn (nouveau pays) FOLLOWED BY New-InboxRule (60 min)                  |
| Activité suspecte (BEC)  | UserLoggedIn (nouvelle IP) FOLLOWED BY MailItemsAccessed FOLLOWED BY Send       |
| Tentative de force brute | Multiple failed logins FOLLOWED BY successful login (même IP)                   |

## Conclusion

L’investigation du lab BEC-KY met en évidence une attaque de type Business Email Compromise visant un compte disposant de privilèges financiers importants.

L’acteur malveillant a utilisé un courriel de phishing et un faux portail Microsoft pour obtenir un accès au compte du CFO. Il s’est ensuite connecté depuis deux adresses IP distinctes, a accédé à la boîte aux lettres et a créé des règles permettant de supprimer ou de déplacer les messages relatifs aux retraits financiers.

La compromission de la messagerie a ainsi permis de dissimuler une fraude impliquant plusieurs virements, dont une transaction prouvée vers First Bank of Nigeria.

Au-delà des indicateurs techniques, cet incident démontre que la détection d’un BEC doit reposer sur la corrélation de plusieurs types de données :

- Courriels
- Authentifications
- Sessions
- Règles de boîte
- Accès aux messages
- Contexte financier

La leçon méthodologique principale de ce lab est qu’une adresse IP ne peut à elle seule déterminer le caractère malveillant d’une opération.

Nous avons utilisé une chaîne de preuves : action anormale ou malveillante → authentification → adresse IP

