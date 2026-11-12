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
| Sauvegardes | Dumps `getfacl -R` gzip dans `/var/lib/cockpit-zfs/permission-backups` |
| Préréglages | `posixacl-smb`, `noacl-unix`, `macos-smb`, `nfsv4` avec plan des `zfs set` |

## Méthodes de réinitialisation

| Méthode | Effet |
|---|---|
| `unix-mode` | chown + chmod fichiers / dossiers séparés, setgid / sticky, conservation du x, retrait des ACL |
| `strip-acl` | `setfacl -b` (option : garder l'ACL par défaut) |
| `acl-template` | ACL modèle (u/g/o + entrées nommées + masque), héritable sur les dossiers, `X` sur les fichiers |
| `inherit-parent` | l'ACL par défaut de la racine remplace l'ACL de tous les descendants |
| `mirror-reference` | copie propriétaire / mode / ACL d'un dossier et d'un fichier de référence |
| `from-snapshot` | relit `.zfs/snapshot/<nom>/` et réapplique propriétaires, modes, setgid / sticky et ACL sans toucher aux données |
| `from-backup` | `setfacl --restore` d'une sauvegarde |
| `clear-ntacl` | retire `security.NTACL` (et `user.DOSATTRIB` en option) écrits par Samba / ksmbd `acl_xattr` |
| `orphans` | réattribue seulement les objets à UID / GID inexistant |
| `takeown` | chown récursif en préservant setuid / setgid |
| `chattr-clear` | retire immutable / append-only (ioctl `FS_IOC_SETFLAGS`) |

## Portée commune

Récursif, profondeur max., fichiers / dossiers seulement, motifs glob inclure / exclure
(un dossier exclu est élagué), et **les datasets enfants ne sont pas traversés par défaut**
(comparaison de `st_dev`). Les liens symboliques ne sont jamais suivis, `.zfs` est ignoré,
`/` et les chemins de snapshot sont refusés en écriture.

## Notes ZFS sous Linux

- `aclinherit` / `aclmode` ne s'appliquent qu'aux ACL NFSv4 : sans effet en `posixacl`.
- `acltype=off` n'efface pas les ACL déjà stockées : l'audit les signale (« ACL POSIX ignorées »).
- `xattr=sa` est fortement recommandé avec `posixacl` (sinon chaque ACL est un fichier caché).

## Dépendances

Paquet `acl` (`getfacl` / `setfacl`), ajouté au manifeste.

## Tests

```bash
sudo python3 -m unittest zfs/tests/test_zfs_permissions.py -v
```

Les tests utilisent un faux binaire `zfs` et un dossier temporaire sur un système de
fichiers avec ACL POSIX (ext4, xfs ou zfs).
