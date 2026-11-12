<template>
	<div class="space-y-3">
		<!-- Sélection du dataset et du chemin -->
		<Card :titleSection="true" :contentSection="true" :footerSection="false" bgColor="bg-default">
			<template #title>
				<div class="text-lg font-semibold text-default">Permissions</div>
			</template>
			<template #content>
				<div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
					<div>
						<label class="block text-default">Dataset</label>
						<select v-model="selectedDataset" class="input-textlike bg-default w-full">
							<option value="" disabled>Choisir un dataset…</option>
							<option v-for="d in mountedDatasets" :key="d.name" :value="d.name">{{ d.name }}</option>
						</select>
					</div>
					<div class="md:col-span-2">
						<label class="block text-default">Chemin (dans le dataset)</label>
						<div class="flex flex-row gap-2">
							<input v-model="path" class="input-textlike bg-default w-full font-mono" @keyup.enter="inspect" />
							<button class="btn btn-primary" :disabled="!path || busy" @click="inspect">Inspecter</button>
						</div>
					</div>
				</div>
				<div v-if="state" class="mt-3 grid grid-cols-2 md:grid-cols-6 gap-2 text-sm">
					<div v-for="p in shownProps" :key="p" class="rounded border border-default px-2 py-1">
						<div class="text-xs text-muted">{{ p }}</div>
						<div class="font-mono text-default">
							{{ state.props[p]?.value ?? '—' }}
							<span v-if="state.props[p]?.source === 'local'" class="text-xs text-muted">(local)</span>
						</div>
					</div>
				</div>
				<ul v-if="state?.warnings.length" class="mt-2 text-sm text-warning list-disc pl-5">
					<li v-for="w in state.warnings" :key="w">{{ w }}</li>
				</ul>
			</template>
		</Card>

		<div v-if="state" class="border-b border-default">
			<nav class="-mb-px flex flex-wrap gap-1">
				<a v-for="t in tabs" :key="t.id" @click.prevent="tab = t.id"
					:class="[tab === t.id ? 'border-default text-default' : 'border-transparent text-secondary hover:text-default', 'cursor-pointer whitespace-nowrap border-b-2 py-2 px-3 text-sm font-medium']">
					{{ t.label }}
				</a>
			</nav>
		</div>

		<div v-if="state" class="rounded-lg shadow bg-default p-3">
			<!-- État & ACL -->
			<div v-if="tab === 'acl'" class="space-y-4">
				<div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
					<div><span class="text-muted">Type</span> <span class="text-default">{{ state.info.type }}</span></div>
					<div><span class="text-muted">Mode</span> <span class="font-mono text-default">{{ state.info.mode }} {{ state.info.symbolic }}</span></div>
					<div><span class="text-muted">Propriétaire</span> <span class="text-default">{{ state.info.owner ?? state.info.uid + ' (orphelin)' }}</span></div>
					<div><span class="text-muted">Groupe</span> <span class="text-default">{{ state.info.group ?? state.info.gid + ' (orphelin)' }}</span></div>
					<div v-if="state.info.immutable" class="text-danger">immutable</div>
					<div v-if="state.info.has_ntacl" class="text-warning">ACL NT (security.NTACL)</div>
					<div v-if="state.info.xattrs.length" class="md:col-span-4 text-xs text-muted">
						xattrs : <span class="font-mono">{{ state.info.xattrs.join(', ') }}</span>
					</div>
				</div>
				<AclEditor :path="state.path" :acl="state.acl" :aclMode="state.acl_mode" :isDir="state.info.type === 'dir'" @changed="inspect" />
				<details v-if="state.children.length" class="text-sm">
					<summary class="cursor-pointer text-default font-medium">Contenu ({{ state.children.length }})</summary>
					<table class="w-full mt-1 text-xs">
						<thead><tr class="text-left text-muted"><th>Nom</th><th>Mode</th><th>Propriétaire</th><th>Groupe</th><th>Indicateurs</th></tr></thead>
						<tbody>
							<tr v-for="c in state.children" :key="c.path" class="border-t border-default hover:bg-accent cursor-pointer"
								@click="open(c.path)">
								<td class="font-mono py-0.5 text-default">{{ basename(c.path) }}{{ c.type === 'dir' ? '/' : '' }}</td>
								<td class="font-mono text-default">{{ c.symbolic }}</td>
								<td class="text-default">{{ c.owner ?? c.uid }}</td>
								<td class="text-default">{{ c.group ?? c.gid }}</td>
								<td class="text-muted">{{ flags(c) }}</td>
							</tr>
						</tbody>
					</table>
				</details>
			</div>

			<!-- Réinitialisation -->
			<ResetPanel v-else-if="tab === 'reset'" :path="state.path" :dataset="state.dataset" :aclMode="state.acl_mode" @changed="inspect" />

			<!-- Audit -->
			<div v-else-if="tab === 'audit'" class="space-y-3 text-sm">
				<div class="flex flex-row gap-3 items-center">
					<button class="btn btn-primary" :disabled="busy" @click="audit">Lancer l'audit</button>
					<label class="flex items-center gap-2 text-default">
						<input type="checkbox" v-model="auditCross" class="input-checkbox" /> Traverser les datasets enfants
					</label>
					<label class="flex items-center gap-2 text-default">
						<input type="checkbox" v-model="auditFlags" class="input-checkbox" /> Vérifier immutable (plus lent)
					</label>
				</div>
				<template v-if="auditResult">
					<div class="text-default">
						{{ auditResult.total }} objets ({{ auditResult.dirs }} dossiers, {{ auditResult.files }} fichiers)
						<span v-if="auditResult.truncated" class="text-warning">— tronqué</span>
					</div>
					<div class="grid grid-cols-1 md:grid-cols-2 gap-2">
						<details v-for="(label, key) in findingLabels" :key="key" class="rounded border border-default p-2"
							:class="{ 'opacity-50': !auditResult.counts[key] }">
							<summary class="cursor-pointer text-default">
								{{ label }} : <span class="font-semibold">{{ auditResult.counts[key] ?? 0 }}</span>
							</summary>
							<ul class="font-mono text-xs mt-1 max-h-48 overflow-auto">
								<li v-for="p in auditResult.findings[key]" :key="p" class="break-all cursor-pointer hover:underline text-default" @click="open(p)">{{ p }}</li>
							</ul>
						</details>
					</div>
					<div class="grid grid-cols-1 md:grid-cols-3 gap-3">
						<div>
							<div class="font-medium text-default">Propriétaires</div>
							<div v-for="o in auditResult.owners" :key="o.id" class="flex justify-between text-default">
								<span>{{ o.name ?? o.id + ' (orphelin)' }}</span><span>{{ o.count }}</span>
							</div>
						</div>
						<div>
							<div class="font-medium text-default">Groupes</div>
							<div v-for="g in auditResult.groups" :key="g.id" class="flex justify-between text-default">
								<span>{{ g.name ?? g.id + ' (orphelin)' }}</span><span>{{ g.count }}</span>
							</div>
						</div>
						<div>
							<div class="font-medium text-default">Modes</div>
							<div v-for="m in auditResult.modes" :key="m.mode + m.kind" class="flex justify-between font-mono text-default">
								<span>{{ m.mode }} {{ m.kind }}</span><span>{{ m.count }}</span>
							</div>
						</div>
					</div>
				</template>
			</div>

			<!-- Délégation zfs allow -->
			<DelegationPanel v-else-if="tab === 'delegation'" :dataset="state.dataset" />

			<!-- Sauvegardes -->
			<div v-else-if="tab === 'backups'" class="text-sm space-y-2">
				<p class="text-muted">
					Dumps <span class="font-mono">getfacl -R</span> pris avant chaque réinitialisation, dans
					<span class="font-mono">/var/lib/cockpit-zfs/permission-backups</span>. Restaurez-les depuis l'onglet
					« Réinitialiser » (méthode « Restaurer une sauvegarde »).
				</p>
				<table class="w-full">
					<thead><tr class="text-left text-muted"><th>Date</th><th>Chemin</th><th>Motif</th><th>Entrées</th><th></th></tr></thead>
					<tbody>
						<tr v-for="b in backups" :key="b.id" class="border-t border-default">
							<td class="py-1 text-default">{{ new Date(b.created * 1000).toLocaleString() }}</td>
							<td class="font-mono text-default break-all">{{ b.path }}</td>
							<td class="text-default">{{ b.reason }}</td>
							<td class="text-default">{{ b.entries }}</td>
							<td class="text-right"><button class="text-danger text-xs" @click="removeBackup(b.id)">supprimer</button></td>
						</tr>
					</tbody>
				</table>
				<div v-if="!backups.length" class="text-muted">Aucune sauvegarde.</div>
			</div>

			<!-- Préréglages de propriétés -->
			<div v-else-if="tab === 'presets'" class="text-sm space-y-3">
				<p class="text-muted">
					Propriétés ZFS liées aux permissions, appliquées sur <span class="font-mono">{{ state.dataset }}</span>.
					Sous Linux, <span class="font-mono">aclinherit</span> et <span class="font-mono">aclmode</span> ne
					concernent que les ACL NFSv4 : ils sont sans effet en <span class="font-mono">posixacl</span>.
				</p>
				<div class="flex flex-row gap-2 items-end">
					<div>
						<label class="block text-default">Préréglage</label>
						<select v-model="preset" class="input-textlike bg-default">
							<option v-for="(label, id) in presets" :key="id" :value="id">{{ label }}</option>
						</select>
					</div>
					<button class="btn btn-secondary" :disabled="busy" @click="runPreset(true)">Simuler</button>
					<button class="btn btn-primary" :disabled="busy || !presetPlan?.commands.length" @click="runPreset(false)">Appliquer</button>
				</div>
				<div v-if="presetPlan" class="rounded border border-default p-2">
					<div v-for="c in presetPlan.changes" :key="c.prop" class="font-mono text-default">
						{{ c.prop }} : {{ c.from }} → {{ c.to }} <span v-if="c.note" class="text-warning font-sans">({{ c.note }})</span>
					</div>
					<div v-if="!presetPlan.changes.length" class="text-success">Déjà conforme.</div>
					<pre v-if="presetPlan.commands.length" class="font-mono text-xs mt-2 text-default">{{ presetPlan.commands.join('\n') }}</pre>
					<ul class="list-disc pl-5 text-muted mt-1"><li v-for="n in presetPlan.notes" :key="n">{{ n }}</li></ul>
					<div v-for="e in presetPlan.errors ?? []" :key="e.command" class="text-danger">{{ e.command }} : {{ e.error }}</div>
				</div>
			</div>
		</div>
	</div>
</template>

<script setup lang="ts">
import { ref, computed, inject, watch, type Ref } from 'vue';
import { pushNotification, Notification } from '@45drives/houston-common-ui';
import type { ZFSFileSystemInfo } from '@45drives/houston-common-lib';
import Card from '../common/Card.vue';
import AclEditor from './AclEditor.vue';
import ResetPanel from './ResetPanel.vue';
import DelegationPanel from './DelegationPanel.vue';
import {
	type InspectResult, type AuditResult, type BackupMeta, type PathInfo,
	inspectPath, auditPath, listBackups, deleteBackup, applyPreset,
} from '../../composables/permissions';

const datasets = inject<Ref<ZFSFileSystemInfo[]>>('datasets')!;

const mountedDatasets = computed(() =>
	(datasets?.value ?? []).filter((d: any) => d.mountpoint && String(d.mountpoint).startsWith('/')));

const selectedDataset = ref('');
const path = ref('');
const state = ref<InspectResult | null>(null);
const busy = ref(false);
const tab = ref<'acl' | 'reset' | 'audit' | 'delegation' | 'backups' | 'presets'>('acl');
const tabs = [
	{ id: 'acl', label: 'État & ACL' },
	{ id: 'reset', label: 'Réinitialiser' },
	{ id: 'audit', label: 'Audit' },
	{ id: 'delegation', label: 'Délégation zfs allow' },
	{ id: 'backups', label: 'Sauvegardes' },
	{ id: 'presets', label: 'Préréglages' },
] as const;
const shownProps = ['acltype', 'xattr', 'aclinherit', 'aclmode', 'dnodesize', 'normalization'];

watch(selectedDataset, (name) => {
	const ds: any = mountedDatasets.value.find((d: any) => d.name === name);
	if (ds) {
		path.value = ds.mountpoint;
		inspect();
	}
});

async function inspect() {
	if (!path.value) return;
	busy.value = true;
	try {
		state.value = await inspectPath(path.value);
		path.value = state.value.path;
		if (state.value.dataset !== selectedDataset.value) selectedDataset.value = state.value.dataset;
	} catch (e: any) {
		pushNotification(new Notification('Inspection impossible', e.message, 'error', 6000));
	} finally {
		busy.value = false;
	}
}

function open(p: string) {
	path.value = p;
	tab.value = 'acl';
	inspect();
}

const basename = (p: string) => p.split('/').pop();
const flags = (c: PathInfo) => [
	c.setgid && 'setgid', c.sticky && 'sticky', c.has_posix_acl && 'ACL', c.has_ntacl && 'NTACL', c.immutable && 'immutable',
].filter(Boolean).join(' ');

// ---- audit
const auditResult = ref<AuditResult | null>(null);
const auditCross = ref(false);
const auditFlags = ref(true);
const findingLabels: Record<string, string> = {
	world_writable: 'Inscriptibles par tous (sans sticky)',
	orphan_uid: 'UID orphelins',
	orphan_gid: 'GID orphelins',
	foreign_group: 'Groupe différent de la racine',
	dir_missing_setgid: 'Dossiers sans setgid (racine setgid)',
	posix_acl: 'Avec ACL POSIX étendues',
	ignored_posix_acl: 'ACL POSIX ignorées (acltype=off)',
	ntacl: 'Avec ACL NT (security.NTACL)',
	immutable: 'Immutable / append-only',
	setuid: 'Fichiers setuid / setgid',
};
async function audit() {
	busy.value = true;
	try {
		auditResult.value = await auditPath(state.value!.path, { cross_datasets: auditCross.value, check_flags: auditFlags.value });
	} catch (e: any) {
		pushNotification(new Notification('Audit impossible', e.message, 'error', 6000));
	} finally {
		busy.value = false;
	}
}

// ---- sauvegardes
const backups = ref<BackupMeta[]>([]);
async function loadBackups() {
	try { backups.value = (await listBackups()).backups; } catch { backups.value = []; }
}
async function removeBackup(id: string) {
	try {
		await deleteBackup(id);
		await loadBackups();
	} catch (e: any) {
		pushNotification(new Notification('Suppression impossible', e.message, 'error', 6000));
	}
}

// ---- préréglages
const presets: Record<string, string> = {
	'posixacl-smb': 'ACL POSIX pour SMB (Samba / ksmbd acl_xattr)',
	'noacl-unix': 'Droits Unix seulement (noacl)',
	'macos-smb': 'Partage fréquenté par macOS',
	'nfsv4': 'ACL NFSv4 (FreeBSD / TrueNAS seulement)',
};
const preset = ref('posixacl-smb');
const presetPlan = ref<Awaited<ReturnType<typeof applyPreset>> | null>(null);
async function runPreset(dryRun: boolean) {
	busy.value = true;
	try {
		presetPlan.value = await applyPreset(state.value!.dataset, preset.value, dryRun);
		if (!dryRun) {
			pushNotification(new Notification('Préréglage appliqué', presetPlan.value.commands.join('\n') || 'Aucun changement',
				presetPlan.value.errors?.length ? 'warning' : 'success', 6000));
			await inspect();
		}
	} catch (e: any) {
		pushNotification(new Notification('Préréglage impossible', e.message, 'error', 6000));
	} finally {
		busy.value = false;
	}
}
watch(preset, () => (presetPlan.value = null));

watch(tab, (t) => {
	if (t === 'backups') loadBackups();
});
</script>
