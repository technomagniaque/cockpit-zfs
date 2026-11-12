<template>
	<div class="space-y-4">
		<div>
			<label class="block text-sm font-medium text-default">Méthode de réinitialisation</label>
			<select v-model="method" class="input-textlike bg-default w-full md:w-2/3">
				<option v-for="m in methodList" :key="m.id" :value="m.id">{{ m.label }}</option>
			</select>
			<p class="text-sm text-muted mt-1">{{ current.help }}</p>
			<p v-if="current.posixOnly && aclMode !== 'posix'" class="text-sm text-danger mt-1">
				Cette méthode exige <span class="font-mono">acltype=posixacl</span> (actuel : {{ aclMode }}).
			</p>
		</div>

		<div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
			<template v-for="f in current.fields" :key="f.key">
				<label v-if="f.type === 'bool'" class="flex items-center gap-2 text-default" :title="f.help">
					<input type="checkbox" v-model="opts[f.key]" class="input-checkbox" />
					{{ f.label }}
				</label>
				<div v-else-if="f.type === 'snapshot'">
					<label class="block text-default">{{ f.label }}</label>
					<select v-model="opts[f.key]" class="input-textlike bg-default w-full">
						<option value="" disabled>{{ snapshots.length ? 'Choisir…' : 'Aucun snapshot' }}</option>
						<option v-for="s in snapshots" :key="s" :value="s">{{ s.split('@')[1] }}</option>
					</select>
				</div>
				<div v-else-if="f.type === 'backup'">
					<label class="block text-default">{{ f.label }}</label>
					<select v-model="opts[f.key]" class="input-textlike bg-default w-full">
						<option value="" disabled>{{ backups.length ? 'Choisir…' : 'Aucune sauvegarde' }}</option>
						<option v-for="b in backups" :key="b.id" :value="b.id">
							{{ new Date(b.created * 1000).toLocaleString() }} — {{ b.path }} ({{ b.reason }})
						</option>
					</select>
				</div>
				<div v-else-if="f.type === 'perms'">
					<label class="block text-default">{{ f.label }}</label>
					<input v-model="opts[f.key]" class="input-textlike bg-default w-full font-mono" maxlength="3" />
				</div>
				<div v-else-if="f.type === 'entries'" class="md:col-span-3">
					<label class="block text-default">{{ f.label }}</label>
					<div v-for="(e, i) in opts[f.key]" :key="i" class="flex flex-row gap-2 mt-1">
						<select v-model="e.tag" class="input-textlike bg-default">
							<option value="user">Utilisateur</option>
							<option value="group">Groupe</option>
						</select>
						<input v-model="e.qualifier" placeholder="nom" class="input-textlike bg-default w-48" />
						<input v-model="e.perms" class="input-textlike bg-default w-20 font-mono" maxlength="3" />
						<button class="text-danger text-xs" @click="opts[f.key].splice(i, 1)">retirer</button>
					</div>
					<button class="btn btn-secondary mt-2" @click="opts[f.key].push({ tag: 'group', qualifier: '', perms: 'rwx' })">
						Ajouter une entrée
					</button>
				</div>
				<div v-else>
					<label class="block text-default">{{ f.label }}</label>
					<input v-model="opts[f.key]" :placeholder="f.placeholder" class="input-textlike bg-default w-full"
						:class="{ 'font-mono': f.type === 'mode' || f.type === 'path' }" :title="f.help" />
				</div>
			</template>
		</div>

		<details class="text-sm" :open="false">
			<summary class="cursor-pointer text-default font-medium">Portée (récursion, filtres, datasets enfants)</summary>
			<div class="mt-2"><WalkOptionsForm :modelValue="walk" /></div>
		</details>

		<label v-if="method !== 'from-backup'" class="flex items-center gap-2 text-sm text-default">
			<input type="checkbox" v-model="backup" class="input-checkbox" />
			Sauvegarder l'état de chaque objet avant de le modifier (restaurable)
		</label>

		<div class="flex flex-row gap-2">
			<button class="btn btn-secondary" :disabled="busy" @click="run(true)">Simuler</button>
			<button class="btn btn-danger" :disabled="busy" @click="run(false)">
				{{ confirmPending ? 'Confirmer : modifier ' + (plan?.count ?? '?') + ' objet(s)' : 'Appliquer' }}
			</button>
			<span v-if="busy" class="text-sm text-muted self-center">Traitement…</span>
		</div>
		<PlanView :plan="plan" />
	</div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, onMounted } from 'vue';
import { pushNotification, Notification } from '@45drives/houston-common-ui';
import WalkOptionsForm from './WalkOptionsForm.vue';
import PlanView from './PlanView.vue';
import {
	type ResetMethod, type PlanResult, type WalkOptions, type BackupMeta,
	resetPermissions, listBackups, listDatasetSnapshots,
} from '../../composables/permissions';

const props = defineProps<{ path: string; dataset: string; aclMode: string }>();
const emit = defineEmits<{ (e: 'changed'): void }>();

type FieldType = 'text' | 'mode' | 'bool' | 'perms' | 'entries' | 'snapshot' | 'backup' | 'path';
interface Field { key: string; label: string; type: FieldType; default: any; help?: string; placeholder?: string }
interface MethodDef { id: ResetMethod; label: string; help: string; posixOnly?: boolean; fields: Field[] }

const owner: Field = { key: 'owner', label: 'Propriétaire (vide = inchangé)', type: 'text', default: '', placeholder: 'utilisateur ou UID' };
const group: Field = { key: 'group', label: 'Groupe (vide = inchangé)', type: 'text', default: '', placeholder: 'groupe ou GID' };

const methodList: MethodDef[] = [
	{
		id: 'unix-mode', label: 'Mode Unix uniforme',
		help: 'chown + chmod avec des modes distincts pour fichiers et dossiers. Option setgid pour que les nouveaux fichiers héritent du groupe du dossier (équivalent pratique de l\'héritage en noacl).',
		fields: [owner, group,
			{ key: 'file_mode', label: 'Mode fichiers', type: 'mode', default: '0664' },
			{ key: 'dir_mode', label: 'Mode dossiers', type: 'mode', default: '0775' },
			{ key: 'setgid_dirs', label: 'setgid sur les dossiers (g+s)', type: 'bool', default: true },
			{ key: 'sticky_dirs', label: 'sticky bit sur les dossiers (+t)', type: 'bool', default: false, help: 'Seul le propriétaire peut supprimer ses fichiers' },
			{ key: 'keep_exec', label: 'Conserver x sur les fichiers déjà exécutables', type: 'bool', default: true },
			{ key: 'strip_acl', label: 'Retirer aussi les ACL étendues', type: 'bool', default: true }],
	},
	{
		id: 'strip-acl', label: 'Retirer les ACL étendues', posixOnly: true,
		help: 'setfacl -b : retire toutes les entrées nommées, le masque et l\'ACL par défaut. Le mode Unix reste.',
		fields: [{ key: 'keep_default', label: 'Garder l\'ACL par défaut des dossiers', type: 'bool', default: false }],
	},
	{
		id: 'acl-template', label: 'Modèle d\'ACL', posixOnly: true,
		help: 'Remplace l\'ACL de chaque objet par un modèle : propriétaire / groupe / autres + entrées nommées, avec ACL par défaut héritable sur les dossiers. Sur les fichiers, x devient X (exécutable seulement s\'il l\'était).',
		fields: [owner, group,
			{ key: 'owner_perms', label: 'Droits propriétaire', type: 'perms', default: 'rwx' },
			{ key: 'group_perms', label: 'Droits groupe', type: 'perms', default: 'rwx' },
			{ key: 'other_perms', label: 'Droits autres', type: 'perms', default: '---' },
			{ key: 'mask_perms', label: 'Masque', type: 'perms', default: 'rwx' },
			{ key: 'inherit', label: 'ACL par défaut héritable sur les dossiers', type: 'bool', default: true },
			{ key: 'setgid_dirs', label: 'setgid sur les dossiers', type: 'bool', default: true },
			{ key: 'entries', label: 'Entrées nommées', type: 'entries', default: [] }],
	},
	{
		id: 'inherit-parent', label: 'Propager l\'héritage du dossier racine', posixOnly: true,
		help: 'Comme « Remplacer toutes les permissions des objets enfants » sous Windows : l\'ACL par défaut du chemin choisi devient l\'ACL d\'accès + par défaut de chaque descendant.',
		fields: [
			{ key: 'fallback_access', label: 'Utiliser l\'ACL d\'accès si pas d\'ACL par défaut', type: 'bool', default: false },
			{ key: 'keep_exec', label: 'x conditionnel (X) sur les fichiers', type: 'bool', default: true },
			{ key: 'reset_owner_to_root', label: 'Aligner propriétaire / groupe sur la racine', type: 'bool', default: false }],
	},
	{
		id: 'mirror-reference', label: 'Copier depuis une référence',
		help: 'Applique propriétaire, mode et ACL d\'un dossier (et d\'un fichier) de référence à tout l\'arbre. Sans fichier de référence, les fichiers reçoivent le modèle du dossier avec x seulement s\'ils étaient déjà exécutables. Une référence qui est un lien symbolique est refusée.',
		fields: [
			{ key: 'reference_dir', label: 'Dossier de référence', type: 'path', default: '', placeholder: '/tank/modele' },
			{ key: 'reference_file', label: 'Fichier de référence (vide = dossier)', type: 'path', default: '' },
			{ key: 'copy_owner', label: 'Copier aussi propriétaire / groupe', type: 'bool', default: true }],
	},
	{
		id: 'from-snapshot', label: 'Restaurer depuis un snapshot ZFS',
		help: 'Relit propriétaires, modes, setgid/sticky et ACL dans .zfs/snapshot/<nom>/ et les réapplique aux fichiers actuels. Les données ne sont pas touchées ; les fichiers créés depuis le snapshot et les datasets enfants sont ignorés.',
		fields: [{ key: 'snapshot', label: 'Snapshot', type: 'snapshot', default: '' }],
	},
	{
		id: 'from-backup', label: 'Restaurer une sauvegarde de permissions',
		help: 'Réapplique l\'état enregistré avant une réinitialisation ou une édition d\'ACL (propriétaire, mode, ACL, ACL NT, attributs DOS, immutable). Les objets remplacés par un lien ou passés dans un autre dataset sont ignorés.',
		fields: [{ key: 'backup_id', label: 'Sauvegarde', type: 'backup', default: '' }],
	},
	{
		id: 'clear-ntacl', label: 'Effacer les ACL NT (Samba / ksmbd)',
		help: 'Retire security.NTACL écrit par acl_xattr : le serveur SMB recalcule alors l\'ACL Windows à partir des droits POSIX. À faire après une migration Samba ↔ ksmbd ou si l\'onglet Sécurité de Windows ne reflète plus la réalité.',
		fields: [{ key: 'dosattrib', label: 'Retirer aussi user.DOSATTRIB (attributs caché / archive…)', type: 'bool', default: false }],
	},
	{
		id: 'orphans', label: 'Réattribuer les propriétaires orphelins',
		help: 'Ne touche que les objets dont l\'UID ou le GID ne correspond plus à aucun compte (après import d\'un pool ou suppression d\'utilisateurs).',
		fields: [owner, group],
	},
	{
		id: 'takeown', label: 'Changer propriétaire / groupe (récursif)',
		help: 'chown récursif sans modifier les modes ni les ACL. Les bits setuid / setgid sont réappliqués après le chown.',
		fields: [owner, group, { key: 'preserve_setid', label: 'Préserver setuid / setgid', type: 'bool', default: true }],
	},
	{
		id: 'chattr-clear', label: 'Retirer immutable / append-only',
		help: 'Retire les attributs chattr +i / +a qui bloquent toute modification, y compris par root.',
		fields: [],
	},
];

const method = ref<ResetMethod>('unix-mode');
const current = computed(() => methodList.find((m) => m.id === method.value)!);
const opts = reactive<Record<string, any>>({});
const walk = reactive<WalkOptions>({ recursive: true, include_root: true, cross_datasets: false, types: 'all', include: [], exclude: [], max_depth: null });
const backup = ref(true);
const busy = ref(false);
const confirmPending = ref(false);
const plan = ref<PlanResult | null>(null);
const snapshots = ref<string[]>([]);
const backups = ref<BackupMeta[]>([]);
/** paramètres exacts de la dernière simulation réussie */
const simulatedKey = ref<string | null>(null);

function buildOptions(): Record<string, unknown> {
	const options: Record<string, unknown> = { ...walk, ...opts, backup: backup.value };
	if (method.value === 'acl-template') {
		options.entries = (opts.entries ?? []).filter((e: any) => e.qualifier);
	}
	return options;
}
const currentKey = () => JSON.stringify({ m: method.value, p: props.path, o: buildOptions() });

function disarm() {
	confirmPending.value = false;
	simulatedKey.value = null;
}

function loadDefaults() {
	for (const k of Object.keys(opts)) delete opts[k];
	for (const f of current.value.fields) opts[f.key] = Array.isArray(f.default) ? [] : f.default;
	plan.value = null;
	disarm();
}
watch(method, loadDefaults, { immediate: true });
// toute modification après la simulation désarme la confirmation
watch([opts, walk, backup, () => props.path], () => {
	if (simulatedKey.value !== null && simulatedKey.value !== currentKey()) {
		disarm();
		plan.value = null;
	}
}, { deep: true });

async function refreshSources() {
	snapshots.value = props.dataset ? await listDatasetSnapshots(props.dataset) : [];
	try { backups.value = (await listBackups()).backups; } catch { backups.value = []; }
}
watch(() => props.dataset, refreshSources);
onMounted(refreshSources);

async function simulate(): Promise<boolean> {
	disarm();
	plan.value = null;
	const key = currentKey();
	busy.value = true;
	try {
		plan.value = await resetPermissions(method.value, props.path, buildOptions(), true);
		simulatedKey.value = key;
		return true;
	} catch (e: any) {
		pushNotification(new Notification('Échec de la simulation', e.message, 'error', 8000));
		return false;
	} finally {
		busy.value = false;
	}
}

async function run(dryRun: boolean) {
	if (dryRun) {
		await simulate();
		return;
	}
	// 1re pression : simulation ; la confirmation n'est armée que si elle réussit
	if (!confirmPending.value || simulatedKey.value !== currentKey()) {
		if (await simulate()) confirmPending.value = true;
		return;
	}
	confirmPending.value = false;
	busy.value = true;
	try {
		plan.value = await resetPermissions(method.value, props.path, buildOptions(), false);
		simulatedKey.value = null;
		pushNotification(new Notification('Permissions réinitialisées',
			`${current.value.label} : ${plan.value.count} changement(s)` + (plan.value.backup ? ` — sauvegarde ${plan.value.backup.id}` : ''),
			plan.value.error_count ? 'warning' : 'success', 6000));
		emit('changed');
		refreshSources();
	} catch (e: any) {
		pushNotification(new Notification('Échec de la réinitialisation', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}
</script>
