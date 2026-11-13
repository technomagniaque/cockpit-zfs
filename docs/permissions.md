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

OpenZFS upstream sous Linux n'a **pas** d'ACL NFSv4 natives : `acltype=nfsv4` n'existe que
sur FreeBSD et sur les piles patchées (TrueNAS ; PR openzfs/zfs#16967 non fusionnée). Un
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
  `r`, `w`, `a`, `D`, `x` comptent, le reste est reconstruit par le serveur. Un principal inconnu
  donne `NFS4ERR_BADOWNER`.
- **nfs4_setfacl** (nfs4-acl-tools 0.3.x) retire lui-même `f d n i` et `D` sur un fichier,
  marque toujours GROUP@ avec `g`, écrit `n` pour no-propagate et refuse `p` malgré son aide :
  le testeur reproduit ce filtrage (case « client autre » pour Windows / macOS).
- **Audit** : ACE DENY générées, entrées bornées par le masque, entrées nommées sans nom,
  ACL NT, `xattr=dir`, domaine idmapd et `nfs4_disable_idmapping`.
- **Préréglage `nfsv4-posix`** : `acltype=posixacl`, `xattr=sa`, `dnodesize=auto`. Le préréglage
  `nfsv4` détecte une pile patchée (outils `nfs4xdr_*`, dataset déjà en `nfsv4`) et refuse
  sinon d'appliquer.

À prévoir côté export :

- ne pas mettre `no_acl` (les ACL deviendraient invisibles) ;
- `sec=krb5i` ou `krb5p` pour des noms fiables : en `sec=sys` avec `nfs4_disable_idmapping=Y`
  (défaut), les principaux circulent en numérique ;
- même `Domain` dans `/etc/idmapd.conf` côté serveur et clients ;
- NFSv4.1 n'a pas les xattrs utilisateur (NFSv4.2 seulement) : flux `streams_xattr` de ksmbd,
  métadonnées macOS et `security.NTACL` sont invisibles en NFS ; seules les ACL POSIX s'appliquent ;
- knfsd et ksmbd ne coordonnent pas leurs caches : ksmbd gère ses oplocks / baux en interne,
  sans les baux du noyau (`vfs_setlease`) que knfsd utilise pour ses délégations. Éviter
  l'écriture concurrente du même fichier par les deux protocoles.

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
