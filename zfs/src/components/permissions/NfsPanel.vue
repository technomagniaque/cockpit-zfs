<template>
	<div class="space-y-4 text-sm">
		<p class="text-muted">
			Objectif : chaque dataset sous <span class="font-mono">{{ dataset }}</span> accessible en <b>NFSv3 et NFSv4.1</b>.
			NFSv3 ne traverse pas les points de montage (sauf <span class="font-mono">crossmnt</span> /
			<span class="font-mono">nohide</span>) : chaque dataset enfant doit donc avoir son propre export, avec un
			fsid unique, sans doublon entre <span class="font-mono">sharenfs</span> et <span class="font-mono">/etc/exports</span>,
			et en <span class="font-mono">acltype=posixacl</span> (ACL visibles par nfsacl en v3, traduites par knfsd en v4.1).
			Le transport (TCP ou RDMA) se règle côté serveur NFS dans cockpit-file-sharing.
		</p>

		<div class="flex flex-row flex-wrap gap-3 items-center">
			<button class="btn btn-primary" :disabled="busy" @click="load">Analyser</button>
			<label class="flex items-center gap-2 text-default" title="Parcourt tous les fichiers pour trouver les ACL de plus de 1024 entrées">
				<input type="checkbox" v-model="scanAcls" class="input-checkbox" /> analyser toutes les ACL (lent)
			</label>
			<span v-if="busy" class="text-muted">Analyse…</span>
		</div>

		<template v-if="result">
			<div class="text-xs text-muted">Fichiers lus : <span class="font-mono">{{ result.exports_files.join(', ') }}</span></div>
			<table class="w-full text-xs">
				<thead>
					<tr class="text-left text-muted">
						<th class="py-1">Dataset</th><th>Export</th><th>sharenfs</th><th>acltype</th><th>NFSv3</th><th>NFSv4.1</th><th></th>
					</tr>
				</thead>
				<tbody>
					<template v-for="d in result.datasets" :key="d.name">
						<tr class="border-t border-default align-top">
							<td class="py-1 pr-2 font-mono text-default">
								{{ d.name }}
								<div class="text-muted">{{ d.mountpoint }}{{ d.mounted ? '' : ' (non monté)' }}</div>
							</td>
							<td class="pr-2 text-default">
								<div v-for="e in d.exports" :key="e.file + e.line" class="font-mono">
									{{ e.source === 'sharenfs' ? 'zfs.exports' : e.file.split('/').pop() + ':' + e.line }} —
									{{ e.clients.map((c) => `${c.host}(${c.options.join(',')})`).join(' ') }}
								</div>
								<span v-if="!d.exports.length && !d.sharenfs_on" class="text-muted">aucun</span>
							</td>
							<td class="pr-2 font-mono text-default">
								{{ d.sharenfs }}
								<div class="text-muted font-sans">{{ d.sharenfs_source }}</div>
							</td>
							<td class="pr-2 font-mono" :class="d.acltype === 'posixacl' ? 'text-default' : 'text-danger'">{{ d.acltype }}</td>
							<td :class="d.compat.v3 ? 'text-success' : 'text-danger'">{{ d.compat.v3 ? 'oui' : 'non' }}</td>
							<td :class="d.compat.v41 ? 'text-success' : 'text-danger'">{{ d.compat.v41 ? 'oui' : 'non' }}</td>
							<td class="text-right">
								<button class="text-xs text-primary hover:underline" @click="editSharenfs(d)">sharenfs…</button>
							</td>
						</tr>
						<tr v-if="d.findings.length">
							<td colspan="7" class="pb-2">
								<ul class="pl-4 list-disc">
									<li v-for="f in d.findings" :key="f.code + f.message" :class="levelClass[f.level]">{{ f.message }}</li>
								</ul>
							</td>
						</tr>
					</template>
				</tbody>
			</table>
			<ul class="list-disc pl-5 text-xs text-muted">
				<li v-for="n in result.notes" :key="n">{{ n }}</li>
			</ul>
		</template>

		<!-- Générateur d'exports pour les datasets enfants -->
		<div class="rounded-md border border-default p-3 space-y-3">
			<div class="font-semibold text-default">Générer les exports manquants pour les datasets enfants</div>
			<p class="text-xs text-muted">
				Rien n'est écrit : le résultat est à copier dans <span class="font-mono">/etc/exports.d/</span>
				(puis <span class="font-mono">exportfs -ra</span>), ou ce sont des commandes <span class="font-mono">zfs set sharenfs</span>
				que vous pouvez appliquer une à une ci-dessous.
			</p>
			<div class="grid grid-cols-1 md:grid-cols-3 gap-3">
				<div>
					<label class="block text-default">Format</label>
					<select v-model="gen.format" class="input-textlike bg-default w-full">
						<option value="exports">Lignes /etc/exports</option>
						<option value="sharenfs">Valeurs sharenfs</option>
					</select>
				</div>
				<div>
					<label class="block text-default">Clients (séparés par des espaces)</label>
					<input v-model="gen.clients" class="input-textlike bg-default w-full font-mono" placeholder="10.0.0.0/24 hote1" />
				</div>
				<div>
					<label class="block text-default">Options communes</label>
					<input v-model="gen.options" class="input-textlike bg-default w-full font-mono" />
				</div>
				<label class="flex items-center gap-2 text-default">
					<input type="checkbox" v-model="gen.fsid" class="input-checkbox" /> fsid unique dérivé du GUID du dataset
				</label>
				<label class="flex items-center gap-2 text-default">
					<input type="checkbox" v-model="gen.includeExported" class="input-checkbox" /> inclure les datasets déjà exportés
				</label>
			</div>
			<button class="btn btn-secondary" :disabled="busy || !gen.clients.trim()" @click="generate">Générer</button>
			<template v-if="generated">
				<pre class="font-mono text-xs rounded bg-accent p-2 text-default whitespace-pre-wrap">{{ generated.text || '(rien à générer : tous les datasets sont déjà exportés)' }}</pre>
				<div v-if="generated.skipped.length" class="text-xs text-muted">
					Ignorés : {{ generated.skipped.map((s) => `${s.name} (${s.reason})`).join(', ') }}
				</div>
				<ul class="list-disc pl-5 text-xs text-muted"><li v-for="n in generated.notes" :key="n">{{ n }}</li></ul>
				<div v-if="generated.format === 'sharenfs' && generated.commands.length" class="flex flex-row flex-wrap gap-2">
					<button v-for="c in generated.commands" :key="c.name" class="btn btn-secondary text-xs"
						@click="prepareSharenfs(c.name, c.value)">Préparer {{ c.name }}</button>
				</div>
			</template>
		</div>

		<!-- Édition sharenfs -->
		<div v-if="edit.dataset" class="rounded-md border border-default p-3 space-y-2">
			<div class="font-semibold text-default">sharenfs de <span class="font-mono">{{ edit.dataset }}</span></div>
			<p class="text-xs text-muted">
				Syntaxe OpenZFS : <span class="font-mono">rw=@10.0.0.0/24:hote,ro=@…,sec=sys,crossmnt,no_root_squash…</span>
				(hôtes séparés par « : », réseaux préfixés par « @ »). <span class="font-mono">on</span> = rw,crossmnt pour tous.
				sharenfs est hérité par les enfants ; ne gérez pas le même chemin dans cockpit-file-sharing.
			</p>
			<div class="flex flex-row flex-wrap gap-2 items-center">
				<select v-model="edit.op" class="input-textlike bg-default">
					<option value="set">Définir</option>
					<option value="inherit">Hériter (zfs inherit)</option>
				</select>
				<input v-if="edit.op === 'set'" v-model="edit.value" class="input-textlike bg-default w-96 font-mono" placeholder="rw=@10.0.0.0/24,sec=sys" />
				<label class="flex items-center gap-2 text-default" title="Autoriser même si /etc/exports exporte déjà ce chemin">
					<input type="checkbox" v-model="edit.force" class="input-checkbox" /> forcer
				</label>
				<button class="btn btn-secondary" :disabled="busy" @click="runSharenfs(true)">Simuler</button>
				<button class="btn btn-danger" :disabled="busy || !confirmArmed" @click="runSharenfs(false)">
					{{ confirmArmed ? 'Confirmer : ' + sharenfsPlan?.command : 'Appliquer (simulez d\'abord)' }}
				</button>
				<button class="btn btn-secondary" @click="edit.dataset = ''">Fermer</button>
			</div>
			<div v-if="sharenfsPlan" class="text-xs">
				<div class="font-mono text-default">{{ sharenfsPlan.command }}</div>
				<div v-if="sharenfsPlan.current !== undefined" class="text-muted">Actuel : {{ sharenfsPlan.current }} ({{ sharenfsPlan.current_source }})</div>
				<ul class="list-disc pl-5 text-muted"><li v-for="n in sharenfsPlan.notes" :key="n">{{ n }}</li></ul>
				<div v-if="sharenfsPlan.affected && sharenfsPlan.affected.length > 1" class="text-muted">
					Datasets concernés : <span class="font-mono">{{ sharenfsPlan.affected.join(', ') }}</span>
				</div>
				<div v-if="sharenfsPlan.preview && sharenfsPlan.preview.length" class="mt-1">
					<div class="text-muted">Lignes que OpenZFS écrira dans /etc/exports.d/zfs.exports :</div>
					<pre class="font-mono whitespace-pre-wrap text-default">{{ sharenfsPlan.preview.join('\n') }}</pre>
				</div>
			</div>
		</div>
	</div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch } from 'vue';
import { pushNotification, Notification } from '@45drives/houston-common-ui';
import {
	type NfsDatasetsResult, type NfsGenerateResult, type NfsDataset, type SharenfsPlan,
	nfsDatasets, nfsGenerate, nfsSharenfs,
} from '../../composables/permissions';

const props = defineProps<{ dataset: string }>();

const result = ref<NfsDatasetsResult | null>(null);
const busy = ref(false);
const scanAcls = ref(false);
const levelClass: Record<string, string> = { error: 'text-danger', warning: 'text-warning', info: 'text-muted' };

const gen = reactive({ format: 'exports' as 'exports' | 'sharenfs', clients: '', options: 'rw,sync,no_subtree_check,sec=sys', fsid: true, includeExported: false });
const generated = ref<NfsGenerateResult | null>(null);

const edit = reactive({ dataset: '', op: 'set' as 'set' | 'inherit', value: '', force: false });
const sharenfsPlan = ref<SharenfsPlan | null>(null);
const simulatedKey = ref('');
const editKey = computed(() => JSON.stringify([edit.dataset, edit.op, edit.value, edit.force]));
// la confirmation n'est armée qu'après une simulation réussie des paramètres actuels
const confirmArmed = computed(() => !!sharenfsPlan.value?.dry_run && simulatedKey.value === editKey.value);

async function load() {
	if (!props.dataset) return;
	busy.value = true;
	try {
		result.value = await nfsDatasets(props.dataset, scanAcls.value);
	} catch (e: any) {
		pushNotification(new Notification('Analyse NFS impossible', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}
watch(() => props.dataset, () => { result.value = null; generated.value = null; edit.dataset = ''; load(); }, { immediate: true });
watch(gen, () => { generated.value = null; }, { deep: true });
watch(editKey, () => { if (simulatedKey.value !== editKey.value) sharenfsPlan.value = null; });

async function generate() {
	busy.value = true;
	try {
		generated.value = await nfsGenerate({
			dataset: props.dataset, clients: gen.clients.split(/\s+/).filter(Boolean), options: gen.options,
			format: gen.format, fsid: gen.fsid ? 'guid' : 'none', include_exported: gen.includeExported,
		});
	} catch (e: any) {
		pushNotification(new Notification('Génération impossible', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}

function editSharenfs(d: NfsDataset) {
	edit.dataset = d.name;
	edit.op = 'set';
	edit.value = d.sharenfs_on ? d.sharenfs : '';
	edit.force = false;
	sharenfsPlan.value = null;
}

function prepareSharenfs(name: string, value: string) {
	edit.dataset = name;
	edit.op = 'set';
	edit.value = value;
	edit.force = false;
	sharenfsPlan.value = null;
}

async function runSharenfs(dryRun: boolean) {
	busy.value = true;
	const key = editKey.value;
	try {
		if (!dryRun && !confirmArmed.value) return;
		const r = await nfsSharenfs({ dataset: edit.dataset, op: edit.op, value: edit.value, force: edit.force, dry_run: dryRun });
		if (dryRun) {
			sharenfsPlan.value = r;
			simulatedKey.value = key;
		} else {
			sharenfsPlan.value = null;
			simulatedKey.value = '';
			pushNotification(new Notification('sharenfs modifié', r.command, 'success', 6000));
			await load();
		}
	} catch (e: any) {
		sharenfsPlan.value = null;
		simulatedKey.value = '';
		pushNotification(new Notification('sharenfs refusé', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}
</script>
