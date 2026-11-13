<template>
	<div class="space-y-4 text-sm">
		<p class="text-muted">
			Délégation d'administration ZFS (<span class="font-mono">zfs allow</span>) : permet à des utilisateurs non root
			de créer des snapshots, envoyer / recevoir, monter, changer certaines propriétés… sur ce dataset et ses enfants.
		</p>
		<div v-if="loading" class="text-muted">Chargement…</div>
		<template v-else>
			<div v-for="entry in entries" :key="entry.dataset" class="rounded-md border border-default p-3">
				<div class="font-semibold text-default">
					{{ entry.dataset }}
					<span v-if="entry.dataset !== dataset" class="text-xs text-muted">(hérité du parent)</span>
				</div>
				<div v-for="sec in sectionsOf(entry)" :key="sec.key" class="mt-2">
					<div class="text-muted">{{ sec.title }}</div>
					<table class="w-full">
						<tbody>
							<tr v-for="(row, i) in sec.rows" :key="i" class="border-t border-default">
								<td class="py-1 w-48 text-default">{{ row.label }}</td>
								<td class="font-mono text-default">{{ row.perms.join(', ') }}</td>
								<td class="text-right w-20">
									<button v-if="entry.dataset === dataset" class="text-danger text-xs" @click="revoke(sec.key, row)">retirer</button>
								</td>
							</tr>
						</tbody>
					</table>
				</div>
			</div>
			<div v-if="!entries.length" class="text-muted">Aucune délégation sur ce dataset.</div>
		</template>

		<div class="rounded-md border border-default p-3 space-y-3">
			<div class="font-semibold text-default">Ajouter une délégation</div>
			<div class="grid grid-cols-1 md:grid-cols-4 gap-3">
				<div>
					<label class="block text-default">Bénéficiaire</label>
					<select v-model="form.kind" class="input-textlike bg-default w-full">
						<option value="user">Utilisateur (-u)</option>
						<option value="group">Groupe (-g)</option>
						<option value="everyone">Tout le monde (-e)</option>
						<option value="create">Créateur d'un dataset (-c)</option>
						<option value="set">Ensemble nommé (-s @nom)</option>
					</select>
				</div>
				<div v-if="['user', 'group', 'set'].includes(form.kind)">
					<label class="block text-default">{{ form.kind === 'set' ? 'Nom (@nom)' : 'Nom' }}</label>
					<input v-model="form.who" class="input-textlike bg-default w-full" :placeholder="form.kind === 'set' ? '@sauvegarde' : ''" />
				</div>
				<div v-if="['user', 'group', 'everyone'].includes(form.kind)">
					<label class="block text-default">Portée</label>
					<select v-model="form.scope" class="input-textlike bg-default w-full">
						<option value="both">Ce dataset + descendants</option>
						<option value="local">Ce dataset seulement (-l)</option>
						<option value="descendent">Descendants seulement (-d)</option>
					</select>
				</div>
			</div>
			<div>
				<label class="block text-default">Permissions</label>
				<div class="flex flex-row flex-wrap gap-1 mt-1">
					<button v-for="p in quick" :key="p" @click="togglePerm(p)"
						:class="[form.perms.includes(p) ? 'btn-primary' : 'btn-secondary', 'btn text-xs py-0.5 px-2']">{{ p }}</button>
				</div>
				<input v-model="extra" class="input-textlike bg-default w-full mt-2 font-mono"
					placeholder="autres permissions ou @ensembles, séparés par des virgules (ex. compression,quota,@sauvegarde)" />
				<details class="mt-1">
					<summary class="cursor-pointer text-muted">Toutes les permissions connues</summary>
					<div class="font-mono text-xs text-muted mt-1">{{ known.join(', ') }}</div>
				</details>
			</div>
			<div v-if="dangerousForEveryone.length" class="rounded-md border border-red-600 p-2 text-danger space-y-1">
				<div class="font-semibold">Délégation dangereuse à tout le monde</div>
				<div>
					N'importe quel utilisateur du système pourra utiliser <span class="font-mono">{{ dangerousForEveryone.join(', ') }}</span>
					sur ce dataset : recevoir un flux contenant des binaires setuid ou des périphériques, créer et monter des datasets,
					détruire ou renommer des données, ou redéléguer ces droits. Préférez un utilisateur ou un groupe.
				</div>
				<label class="flex flex-row gap-2 items-center">
					<input type="checkbox" v-model="confirmEveryone" />
					<span>Je confirme vouloir déléguer ces permissions à tout le monde</span>
				</label>
			</div>
			<div class="flex flex-row gap-2 items-center">
				<button class="btn btn-primary" :disabled="busy || (dangerousForEveryone.length > 0 && !confirmEveryone)" @click="submit">Déléguer</button>
				<span v-if="preview" class="font-mono text-xs text-muted">{{ preview }}</span>
			</div>
		</div>
	</div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch } from 'vue';
import { pushNotification, Notification } from '@45drives/houston-common-ui';
import { type DelegationEntry, getDelegation, delegate, EVERYONE_DANGEROUS_PERMS } from '../../composables/permissions';

const props = defineProps<{ dataset: string }>();

const entries = ref<DelegationEntry[]>([]);
const known = ref<string[]>([]);
const loading = ref(false);
const busy = ref(false);
const extra = ref('');
const form = reactive({ kind: 'user' as 'user' | 'group' | 'everyone' | 'create' | 'set', who: '', scope: 'both' as 'local' | 'descendent' | 'both', perms: [] as string[] });
const quick = ['snapshot', 'mount', 'send', 'receive', 'hold', 'release', 'create', 'destroy', 'rollback', 'clone', 'promote', 'rename', 'diff', 'userprop', 'load-key', 'change-key', 'compression', 'quota'];

const allPerms = computed(() => [...form.perms, ...extra.value.split(',').map((s) => s.trim()).filter(Boolean)]);
const confirmEveryone = ref(false);
/** Permissions dangereuses demandées pour « tout le monde » (les @ensembles comptent : leur contenu peut changer). */
const dangerousForEveryone = computed(() => form.kind === 'everyone'
	? allPerms.value.filter((p) => EVERYONE_DANGEROUS_PERMS.includes(p) || p.startsWith('@'))
	: []);
watch(dangerousForEveryone, (list) => { if (!list.length) confirmEveryone.value = false; });
const preview = ref('');

function togglePerm(p: string) {
	const i = form.perms.indexOf(p);
	if (i >= 0) form.perms.splice(i, 1); else form.perms.push(p);
}

async function load() {
	if (!props.dataset) return;
	loading.value = true;
	try {
		const r = await getDelegation(props.dataset);
		entries.value = r.entries;
		known.value = r.known_perms;
	} catch (e: any) {
		pushNotification(new Notification('Lecture des délégations impossible', e.message, 'error', 6000));
	} finally {
		loading.value = false;
	}
}
watch(() => props.dataset, load, { immediate: true });

let previewTimer: ReturnType<typeof setTimeout> | undefined;
watch([form, extra], () => {
	clearTimeout(previewTimer);
	if (!allPerms.value.length) { preview.value = ''; return; }
	// aperçu de la commande, avec un délai pour ne pas lancer le backend à chaque frappe
	previewTimer = setTimeout(async () => {
		try {
			preview.value = (await delegate({ dataset: props.dataset, op: 'allow', kind: form.kind, who: form.who, scope: form.scope, perms: allPerms.value, dry_run: true })).command;
		} catch (e: any) {
			preview.value = e.message;
		}
	}, 500);
}, { deep: true });

type SectionKey = 'sets' | 'create' | 'local' | 'descendent' | 'both';
interface Row { label: string; perms: string[]; kind: 'user' | 'group' | 'everyone' | 'create' | 'set'; who: string }

function sectionsOf(e: DelegationEntry) {
	const whoRows = (list: DelegationEntry['local']): Row[] =>
		list.map((w) => ({ label: w.type === 'everyone' ? 'tout le monde' : `${w.type === 'user' ? 'utilisateur' : 'groupe'} ${w.who}`, perms: w.perms, kind: w.type, who: w.who }));
	return ([
		{ key: 'sets', title: 'Ensembles de permissions', rows: e.sets.map((s) => ({ label: s.name, perms: s.perms, kind: 'set', who: s.name })) },
		{ key: 'create', title: 'Permissions du créateur', rows: e.create.map((c) => ({ label: 'créateur', perms: c.perms, kind: 'create', who: '' })) },
		{ key: 'local', title: 'Locales (ce dataset)', rows: whoRows(e.local) },
		{ key: 'descendent', title: 'Descendants', rows: whoRows(e.descendent) },
		{ key: 'both', title: 'Local + descendants', rows: whoRows(e.both) },
	] as { key: SectionKey; title: string; rows: Row[] }[]).filter((s) => s.rows.length);
}

async function revoke(section: SectionKey, row: Row) {
	busy.value = true;
	try {
		const scope = section === 'local' ? 'local' : section === 'descendent' ? 'descendent' : 'both';
		const r = await delegate({ dataset: props.dataset, op: 'unallow', kind: row.kind, who: row.who, scope, perms: row.perms, dry_run: false });
		pushNotification(new Notification('Délégation retirée', r.command, 'success', 5000));
		await load();
	} catch (e: any) {
		pushNotification(new Notification('Retrait impossible', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}

async function submit() {
	busy.value = true;
	try {
		const r = await delegate({
			dataset: props.dataset, op: 'allow', kind: form.kind, who: form.who, scope: form.scope, perms: allPerms.value, dry_run: false,
			confirmer_tout_le_monde: dangerousForEveryone.value.length > 0 && confirmEveryone.value,
		});
		pushNotification(new Notification('Délégation ajoutée', r.command, r.warnings?.length ? 'warning' : 'success', 5000));
		form.perms = [];
		extra.value = '';
		confirmEveryone.value = false;
		await load();
	} catch (e: any) {
		pushNotification(new Notification('Délégation impossible', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}
</script>
