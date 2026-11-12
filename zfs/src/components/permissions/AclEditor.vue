<template>
	<div class="space-y-4">
		<div v-if="aclMode !== 'posix'" class="rounded-md border border-default p-3 text-sm text-default">
			Ce dataset est en <span class="font-mono">acltype={{ aclMode }}</span> : seules les entrées de base
			(propriétaire / groupe / autres) s'appliquent. Utilisez l'onglet « Préréglages » pour passer en
			<span class="font-mono">posixacl</span> si vous avez besoin d'entrées nommées.
		</div>

		<div v-for="section in sections" :key="section.key">
			<div class="flex flex-row justify-between items-center">
				<h4 class="font-semibold text-default">{{ section.title }}</h4>
				<span class="text-xs text-muted">{{ section.hint }}</span>
			</div>
			<table class="w-full text-sm mt-1">
				<thead>
					<tr class="text-left text-muted">
						<th class="py-1">Entrée</th><th class="w-12 text-center">r</th><th class="w-12 text-center">w</th>
						<th class="w-12 text-center">x</th><th class="w-10"></th>
					</tr>
				</thead>
				<tbody>
					<tr v-for="(e, i) in section.entries" :key="section.key + i" class="border-t border-default">
						<td class="py-1 text-default">
							{{ aclEntryLabel(e) }}
							<span v-if="effective(e, section.entries) !== e.perms" class="ml-2 text-xs text-warning"
								title="Droits réellement appliqués après le masque">
								effectif {{ effective(e, section.entries) }}
							</span>
						</td>
						<td v-for="bit in (['r','w','x'] as const)" :key="bit" class="text-center">
							<input type="checkbox" class="input-checkbox" :checked="permsToFlags(e.perms)[bit]"
								@change="toggle(e, bit, ($event.target as HTMLInputElement).checked)" />
						</td>
						<td class="text-right">
							<button v-if="e.qualifier" class="text-danger text-xs" @click="section.entries.splice(i, 1)">retirer</button>
						</td>
					</tr>
				</tbody>
			</table>
			<div v-if="aclMode === 'posix'" class="flex flex-row flex-wrap gap-2 mt-2 items-end text-sm">
				<select v-model="draft[section.key].tag" class="input-textlike bg-default">
					<option value="user">Utilisateur</option>
					<option value="group">Groupe</option>
				</select>
				<input v-model="draft[section.key].qualifier" placeholder="nom ou UID/GID"
					class="input-textlike bg-default w-48" />
				<input v-model="draft[section.key].perms" class="input-textlike bg-default w-20 font-mono" placeholder="r-x" />
				<button class="btn btn-secondary" @click="addEntry(section.key)">Ajouter</button>
				<button v-if="section.key === 'default' && !section.entries.length" class="btn btn-secondary"
					@click="copyAccessToDefault">Copier l'ACL d'accès</button>
			</div>
		</div>

		<div class="border-t border-default pt-3 space-y-3">
			<div class="flex flex-row flex-wrap gap-4 text-sm items-center">
				<label class="text-default">Action
					<select v-model="action" class="input-textlike bg-default ml-1">
						<option value="set">Remplacer (équiv. setfacl --set ; ACL par défaut remplacée si elle est fournie)</option>
						<option value="modify">Fusionner (setfacl -m)</option>
						<option value="remove">Retirer les entrées nommées listées (setfacl -x)</option>
						<option value="remove-default">Retirer l'ACL par défaut (setfacl -k)</option>
					</select>
				</label>
				<label class="flex items-center gap-2 text-default">
					<input type="checkbox" v-model="backup" class="input-checkbox" />
					Sauvegarder avant d'appliquer
				</label>
				<label class="flex items-center gap-2 text-default" title="Sur les fichiers, x devient X : exécutable seulement s'il l'était déjà">
					<input type="checkbox" v-model="conditionalX" class="input-checkbox" />
					x conditionnel (X) sur les fichiers
				</label>
			</div>
			<WalkOptionsForm :modelValue="walk" />
			<div class="flex flex-row gap-2">
				<button class="btn btn-secondary" :disabled="busy || aclMode !== 'posix'" @click="run(true)">Simuler</button>
				<button class="btn btn-primary" :disabled="busy || aclMode !== 'posix'" @click="run(false)">
					{{ confirmPending ? 'Confirmer : modifier ' + (plan?.count ?? '?') + ' objet(s)' : 'Appliquer' }}
				</button>
				<button class="btn btn-secondary" :disabled="busy" @click="resetFromSource">Annuler les modifications</button>
			</div>
			<PlanView :plan="plan" />
		</div>
	</div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch } from 'vue';
import { pushNotification, Notification } from '@45drives/houston-common-ui';
import WalkOptionsForm from './WalkOptionsForm.vue';
import PlanView from './PlanView.vue';
import {
	type AclEntry, type PosixAcl, type PlanResult, type WalkOptions,
	setAcl, permsToFlags, flagsToPerms, aclEntryLabel,
} from '../../composables/permissions';

const props = defineProps<{ path: string; acl: PosixAcl | null; aclMode: string; isDir: boolean }>();
const emit = defineEmits<{ (e: 'changed'): void }>();

const access = ref<AclEntry[]>([]);
const defaults = ref<AclEntry[]>([]);
const action = ref<'set' | 'modify' | 'remove' | 'remove-default'>('set');
const conditionalX = ref(true);
const walk = reactive<WalkOptions>({ recursive: false, include_root: true, cross_datasets: false, types: 'all', include: [], exclude: [], max_depth: null });
const plan = ref<PlanResult | null>(null);
const backup = ref(true);
const simulatedKey = ref<string | null>(null);
const busy = ref(false);
const confirmPending = ref(false);
const draft = reactive<Record<'access' | 'default', AclEntry>>({
	access: { tag: 'user', qualifier: '', perms: 'r-x' },
	default: { tag: 'group', qualifier: '', perms: 'rwx' },
});

const clone = (l: AclEntry[]) => l.map((e) => ({ ...e }));
function resetFromSource() {
	access.value = clone(props.acl?.access ?? []);
	defaults.value = clone(props.acl?.default ?? []);
	plan.value = null;
	confirmPending.value = false;
	simulatedKey.value = null;
}
watch(() => [props.acl, props.path], resetFromSource, { immediate: true });

const sections = computed(() => [
	{ key: 'access' as const, title: "ACL d'accès", hint: 'Droits appliqués à ce chemin', entries: access.value },
	...(props.isDir ? [{ key: 'default' as const, title: 'ACL par défaut (héritée)', hint: 'Copiée sur les nouveaux fichiers / dossiers créés dedans', entries: defaults.value }] : []),
]);

/** Droits effectifs : les entrées nommées et le groupe propriétaire sont bornés par le masque. */
function effective(e: AclEntry, list: AclEntry[]) {
	const mask = list.find((x) => x.tag === 'mask');
	if (!mask || e.tag === 'mask' || e.tag === 'other' || (e.tag === 'user' && !e.qualifier)) return e.perms;
	return [0, 1, 2].map((i) => (e.perms[i] !== '-' && mask.perms[i] !== '-' ? e.perms[i] : '-')).join('');
}

function toggle(e: AclEntry, bit: 'r' | 'w' | 'x', value: boolean) {
	const f = permsToFlags(e.perms);
	f[bit] = value;
	e.perms = flagsToPerms(f);
}

function ensureMask(list: AclEntry[]) {
	if (list.some((e) => e.qualifier) && !list.some((e) => e.tag === 'mask')) {
		const otherIdx = list.findIndex((e) => e.tag === 'other');
		list.splice(otherIdx < 0 ? list.length : otherIdx, 0, { tag: 'mask', qualifier: '', perms: 'rwx' });
	}
}

function addEntry(key: 'access' | 'default') {
	const d = draft[key];
	if (!d.qualifier.trim()) return;
	if (!/^[rwxX-]{3}$/.test(d.perms)) {
		pushNotification(new Notification('Permissions invalides', 'Format attendu : rwx, r-x, rw-…', 'error', 4000));
		return;
	}
	const list = key === 'access' ? access.value : defaults.value;
	if (key === 'default' && !list.length) {
		list.push(...clone(access.value.filter((e) => !e.qualifier)));
	}
	const otherIdx = list.findIndex((e) => e.tag === 'mask' || e.tag === 'other');
	list.splice(otherIdx < 0 ? list.length : otherIdx, 0, { tag: d.tag, qualifier: d.qualifier.trim(), perms: d.perms });
	ensureMask(list);
	d.qualifier = '';
}

function copyAccessToDefault() {
	defaults.value = clone(access.value);
}

function request(dryRun: boolean) {
	ensureMask(access.value);
	ensureMask(defaults.value);
	return {
		path: props.path, action: action.value, access: clone(access.value), default: clone(defaults.value),
		dry_run: dryRun, files_conditional_x: conditionalX.value, backup: backup.value, ...walk,
	};
}
const currentKey = () => JSON.stringify({ ...request(true), dry_run: null });

// toute modification après la simulation désarme la confirmation
watch([access, defaults, action, conditionalX, backup, walk], () => {
	if (simulatedKey.value !== null && simulatedKey.value !== currentKey()) {
		confirmPending.value = false;
		simulatedKey.value = null;
		plan.value = null;
	}
}, { deep: true });

async function simulate(): Promise<boolean> {
	confirmPending.value = false;
	simulatedKey.value = null;
	plan.value = null;
	const key = currentKey();
	busy.value = true;
	try {
		plan.value = await setAcl(request(true));
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
	// simulation obligatoire : la confirmation n'est armée qu'après une simulation réussie
	if (!confirmPending.value || simulatedKey.value !== currentKey()) {
		if (await simulate()) confirmPending.value = true;
		return;
	}
	confirmPending.value = false;
	busy.value = true;
	try {
		plan.value = await setAcl(request(false));
		simulatedKey.value = null;
		pushNotification(new Notification('ACL appliquée', `${plan.value.count} objet(s) modifié(s)` + (plan.value.backup ? ` — sauvegarde ${plan.value.backup.id}` : ''), plan.value.error_count ? 'warning' : 'success', 5000));
		emit('changed');
	} catch (e: any) {
		pushNotification(new Notification('Échec de l\'édition d\'ACL', e.message, 'error', 8000));
	} finally {
		busy.value = false;
	}
}
</script>
