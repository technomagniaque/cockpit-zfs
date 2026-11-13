# Onglet Permissions (branche `feat/permissions-avancees`)

Gestion avancée des permissions sur les datasets ZFS montés, pilotée par
`zfs/src/scripts/zfs-permissions.py` (exécuté en root via cockpit, sortie JSON).

## Sous-onglets

| Sous-onglet | Rôle |
|---|---|
| État & ACL | Mode, propriétaire, xattrs, immutable, ACL d'accès et par défaut éditables (droits effectifs après masque), application récursive filtrée |
| Réinitialiser | 11 méthodes de remise à plat, toutes avec simulation, échantillon et sauvegarde automatique |
| Audit | Parcours complet : inscriptibles par tous, UID/GID orphelins, dossiers sans setgid, ACL ignorées, ACL NT, immutable, setuid, histogrammes |
| Délégation zfs allow | Lecture / ajout / retrait de `zfs allow` (utilisateur, groupe, everyone, créateur, ensembles `@nom`, portée locale / descendants) |
| NFS (v3 + v4.1) | Compatibilité NFSv3 **et** NFSv4.1 de chaque dataset (exports explicites des enfants, fsid, doublons sharenfs / exports, acltype, limite nfsacl), générateur d'exports / sharenfs, édition de sharenfs |
| Sauvegardes | État de chaque objet (propriétaire, mode, ACL brutes, ACL NT, DOSATTRIB, immutable) enregistré juste avant sa modification, dans `/var/lib/cockpit-zfs/permission-backups` |
| Préréglages | `posixacl-smb`, `noacl-unix`, `macos-smb`, `nfsv4` avec plan des `zfs set` |

## Méthodes de réinitialisation

| Méthode | Effet |
|---|---|
| `unix-mode` | chown + chmod fichiers / dossiers séparés, setgid / sticky, conservation du x, retrait des ACL |
| `strip-acl` | équivalent de `setfacl -b` : le groupe reprend l'entrée `group::` réelle (option : garder l'ACL par défaut) |
| `acl-template` | ACL modèle (u/g/o + entrées nommées + masque), héritable sur les dossiers, `X` sur les fichiers |
| `inherit-parent` | l'ACL par défaut de la racine remplace l'ACL de tous les descendants |
| `mirror-reference` | copie propriétaire / mode / ACL d'un dossier et d'un fichier de référence (sans fichier de référence : x seulement si déjà exécutable ; référence-lien refusée) |
| `from-snapshot` | relit `.zfs/snapshot/<nom>/` et réapplique propriétaires, modes, setgid / sticky et ACL sans toucher aux données ; datasets enfants ignorés |
| `from-backup` | réapplique une sauvegarde (objets remplacés par un lien ou passés dans un autre dataset ignorés) |
| `clear-ntacl` | retire `security.NTACL` (et `user.DOSATTRIB` en option) écrits par Samba / ksmbd `acl_xattr` |
| `orphans` | réattribue seulement les objets à UID / GID inexistant (setuid / setgid conservés) |
| `takeown` | chown récursif en préservant setuid / setgid |
| `chattr-clear` | retire immutable / append-only (ioctl `FS_IOC_SETFLAGS`) |

## Sécurité

Le backend tourne en root sur des arbres où des utilisateurs écrivent :

- parcours et modifications **par descripteurs** ouverts composant par composant avec
  `O_NOFOLLOW` (`fchown`, `fchmod`, xattrs `system.posix_acl_*` écrits sur le descripteur) :
  un dossier remplacé par un lien symbolique pendant l'opération ne redirige rien hors de l'arbre ;
- seuls fichiers réguliers et dossiers sont ouverts, jamais périphériques, FIFO ou sockets ;
- écriture refusée sur un chemin qui contient un lien symbolique, sur `/`, et sur les datasets
  système (montés sur `/`, `/usr`, `/var`, `/etc`, `/boot`, `/opt`, `/srv`, `/tmp`…) ;
- `chown` réapplique setuid / setgid que le noyau retire ;
- sortie JSON en ASCII : les noms non UTF-8 (Latin-1 hérité) passent sans erreur.

Dans l'interface, « Appliquer » lance toujours une simulation ; la confirmation n'est armée
qu'après une simulation réussie et se désarme dès qu'une option ou la portée change.
Les liens symboliques du contenu ne sont pas cliquables. Les délégations `zfs allow` sont
en simulation par défaut côté backend.

## Portée commune

Récursif, profondeur max., fichiers / dossiers seulement, motifs glob inclure / exclure
(un dossier exclu est élagué), et **les datasets enfants ne sont pas traversés par défaut**
(comparaison de `st_dev`) ; avec « traverser », seuls les montages ZFS sont suivis. Les liens
symboliques ne sont jamais suivis, `.zfs` est ignoré à la racine de chaque dataset.

## Notes ZFS sous Linux

- `aclinherit` / `aclmode` ne s'appliquent qu'aux ACL NFSv4 : sans effet en `posixacl`.
- `acltype=off` n'efface pas les ACL déjà stockées : l'audit les signale (« ACL POSIX ignorées »).
- `xattr=sa` est fortement recommandé avec `posixacl` (sinon chaque ACL est un fichier caché).

## NFSv4.1

OpenZFS upstream sous Linux n'a **pas** d'ACL NFSv4 natives : `acltype=nfsv4` y est accepté
mais **équivaut à `acltype=off`** (zfsprops(7)) et désactive donc les ACL ; les vraies ACL NFSv4
n'existent que sur FreeBSD et sur les piles patchées (TrueNAS ; PR openzfs/zfs#16967 non fusionnée). Un
partage NFSv4.1 depuis Oracle Linux / UEK repose donc sur les ACL POSIX, que le serveur NFS
du noyau traduit (`fs/nfsd/nfs4acl.c`). Le module reproduit cette traduction à l'identique :

- **POSIX → NFSv4** (`_posix_to_nfsv4_one`, `nfsd4_get_nfs4_acl`) : ordre OWNER@, nommés,
  GROUP@, groupes nommés (ALLOW puis DENY), EVERYONE@ ; ACE DENY générées quand une classe
  suivante a plus de droits ; droits des nommés et du groupe bornés par le masque ; ACL par
  défaut rendue avec les drapeaux `fdi` ; `D` (delete-child) seulement sur les dossiers ;
  `tcy` pour tous, `TC` pour le propriétaire. Visible dans « État & ACL » → « Vue NFSv4 »
  et en infobulle sur chaque enfant.
- **NFSv4 → POSIX** (`nfs4_acl_nfsv4_to_posix`, `process_one_v4_ace`, `posix_state_to_acl`) :
  l'outil « Tester une ACL nfs4_setfacl » dit si knfsd accepte l'ACL, donne l'ACL POSIX et le
  mode stockés, puis ce que le client relira. Refus (EINVAL → `NFS4ERR_ATTRNOTSUPP`) : ACE
  d'audit / d'alarme, drapeaux autres que `f d i g`, héritage sur un fichier. Conversion
  pessimiste : `w` sans `a` (et sans `D` sur un dossier) ne donne pas l'écriture POSIX ; seuls
  `r`, `w`, `a`, `D`, `x` comptent, le reste est reconstruit par le serveur. Les principaux sont
  résolus en premier, comme au décodage XDR : un principal inconnu donne `NFS4ERR_BADOWNER` avant
  toute erreur de traduction ; un principal numérique n'est accepté qu'avec
  `nfs4_disable_idmapping` actif en `sec=sys`, un nom sans `@domaine` est probablement refusé.
  Sur un dossier, une ACL sans ACE héritable **laisse l'ACL par défaut existante en place**
  (`posix_state_to_acl` renvoie NULL, `nfsd_setattr` ne pose l'ACL par défaut que si elle est
  fournie) ; setuid / setgid / sticky sont conservés.
- **Noms** : avec l'idmapping actif, un UID / GID sans nom part comme `Nobody-User` /
  `Nobody-Group` (`nobody` par défaut, `[Mapping]` de idmapd.conf). L'affichage est numérique
  par défaut quand `nfs4_disable_idmapping` n'est pas explicitement `N` (défaut noyau `Y`).
- **Sans ACL POSIX** (`acltype=off`, ou `nfsv4` sous Linux upstream) : knfsd n'annonce pas
  l'attribut ACL (`aclsupport = 0`, `fs/nfsd/nfs4xdr.c`) et refuse tout SETATTR d'ACL
  (`check_attr_support` → `NFS4ERR_ATTRNOTSUPP`, `EOPNOTSUPP` côté client) : `nfs4_getfacl` et
  `nfs4_setfacl` échouent ; la vue NFSv4 l'affiche au lieu d'une ACL OWNER@ / GROUP@ / EVERYONE@.
- **nfs4_setfacl** (nfs4-acl-tools 0.3.x) retire lui-même `f d n i` et `D` sur un fichier,
  marque toujours GROUP@ avec `g`, écrit `n` pour no-propagate et refuse `p` malgré son aide :
  le testeur reproduit ce filtrage (case « client autre » pour Windows / macOS).
- **Audit** : ACE DENY générées, entrées bornées par le masque, entrées nommées sans nom,
  ACL NT, `xattr=dir`, domaine idmapd et `nfs4_disable_idmapping`.
- **Préréglage `nfsv4-posix`** : `acltype=posixacl`, `xattr=sa`, `dnodesize=auto`. Le préréglage
  `nfsv4` ne reconnaît une pile patchée qu'à ses outils (`nfs4xdr_*`) et refuse sinon
  d'appliquer : sous Linux upstream, `acltype=nfsv4` = `acltype=off`.

À prévoir côté export :

- `no_acl` est sans effet sur knfsd récent (`NFSEXP_NOACL` n'est lu nulle part dans `fs/nfsd`) ;
- `sec=krb5i` ou `krb5p` pour des noms fiables : en `sec=sys` avec `nfs4_disable_idmapping=Y`
  (défaut), les principaux circulent en numérique ;
- même `Domain` dans `/etc/idmapd.conf` côté serveur et clients ;
- NFSv4.1 n'a pas les xattrs utilisateur (NFSv4.2 seulement) : flux `streams_xattr` de ksmbd,
  métadonnées macOS et `security.NTACL` sont invisibles en NFS ; seules les ACL POSIX s'appliquent ;
- caches : une ouverture par ksmbd (`dentry_open` → `break_lease`) **casse** bien une
  délégation knfsd ; l'inverse est faux : ksmbd ne pose aucun bail noyau (`vfs_setlease`), ses
  oplocks / baux SMB ne sont jamais rappelés par un accès NFS. Sur un partage double protocole,
  mettre `oplocks = no` côté ksmbd.

## NFSv3 et NFSv4.1 sur tous les datasets

Cible : chaque partage accessible à la fois en NFSv3 et en NFSv4.1 (NFSv4.1 sur RDMA se règle
dans cockpit-file-sharing). Le sous-onglet **NFS (v3 + v4.1)** analyse le dataset choisi et
tous ses descendants (`zfs list -r`) et lit, sans les modifier, `/etc/exports` et
`/etc/exports.d/*.exports` (dont `zfs.exports`, généré par sharenfs).

Ce que montre le code :

- **ACL en NFSv3** : le protocole NFSACL transmet l'ACL POSIX telle quelle
  (`fs/nfsd/nfs3acl.c`, `fs/nfs_common/nfsacl.c`), identifiants en numérique ; une ACL
  minimale reçoit `mask::` = droits du groupe ; au-delà de `NFS_ACL_MAX_ENTRIES` (1024) entrées
  par ACL, `nfsacl_encode` renvoie EINVAL et GETACL échoue. Sans ACL POSIX, GETACL renvoie
  l'ACL minimale du mode et SETACL échoue (`set_posix_acl` → EOPNOTSUPP). Vue « NFSv3 (nfsacl) »
  à côté de la vue NFSv4.1 dans « État & ACL ». Identique en 6.12 (UEK8) et en version actuelle.
- **Points de montage** (`nfsd_cross_mnt`, identique en 6.12) : un client NFSv4 traverse vers
  un dataset enfant **exporté** ; un client NFSv3 ne le fait que si le parent a `crossmnt` ou
  l'enfant `nohide`. Un enfant **non exporté** apparaît comme le dossier vide du point de
  montage, en v3 comme en v4.1. D'où la règle : un export explicite par dataset.
- **sharenfs** (OpenZFS, `lib/libzfs/os/linux/libzfs_share_nfs.c`) : syntaxe Solaris
  (`rw=@réseau:hôte`, `ro=…`, `sec=`, options Linux en liste blanche), `on` = `rw,crossmnt`
  pour tous ; OpenZFS écrit une ligne par hôte dans `/etc/exports.d/zfs.exports` avec
  `sec=sys` par défaut, `no_subtree_check` et `mountpoint` (export seulement si monté), sans fsid.
  La propriété est **héritée** : un `fsid=` dans un sharenfs hérité donne le même fsid aux enfants.

Constats par dataset : enfant non exporté (erreur) ou atteint seulement via `crossmnt`
(avertissement), montage séparé nécessaire en v3, doublon sharenfs + exports, fsid en double ou
hérité, absence de fsid (conseil), export vers tous (`*`), `acltype` autre que `posixacl`,
`xattr=dir`, ACL au-delà de la limite nfsacl (racine du dataset, ou toutes les ACL en option).

**Générer les exports manquants** : lignes `/etc/exports` (chemin échappé comme OpenZFS,
`fsid=<GUID du dataset>` unique et stable) ou valeurs `sharenfs` pour chaque dataset sans
export. Rien n'est écrit : on copie les lignes puis `exportfs -ra`, ou on applique chaque
sharenfs depuis le panneau d'édition (simulation obligatoire, confirmation désarmée si un
paramètre change, `zfs set` / `zfs inherit` avec valeur en liste blanche). Ne gérez pas un même
chemin à la fois par sharenfs et par cockpit-file-sharing / `/etc/exports`.

## Dépendances

Aucune pour le backend (bibliothèque standard Python). Le paquet `acl` reste dans le manifeste
pour les outils `getfacl` / `setfacl` en ligne de commande.

## Tests

```bash
sudo python3 -m unittest zfs/tests/test_zfs_permissions.py -v
```

Les tests utilisent un faux binaire `zfs` et un dossier temporaire sur un système de
fichiers avec ACL POSIX (ext4, xfs ou zfs). Ils couvrent aussi les régressions de sécurité :
dossier remplacé par un lien pendant le parcours (hook `COCKPIT_ZFS_PERM_TEST_RACE`) et pendant
une restauration, dataset enfant (tmpfs monté) non modifié, noms Latin-1, fichiers spéciaux
jamais ouverts.

Les tests NFSv4 comparent aussi le rendu et l'analyse aux vrais `nfs4_getfacl` / `nfs4_setfacl`
(paquet nfs4-acl-tools) grâce à un `LD_PRELOAD` qui remplace l'xattr `system.nfs4_acl` par un
fichier XDR ; ils sont ignorés si nfs4-acl-tools ou gcc manquent.
