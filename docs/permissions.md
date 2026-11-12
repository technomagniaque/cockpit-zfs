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
