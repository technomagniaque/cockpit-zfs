<template>
	<details class="rounded-md border border-default p-3 text-sm" :open="open">
		<summary class="cursor-pointer font-semibold text-default">
			Vue NFS (clients NFSv3 et NFSv4.1)
			<span v-if="view?.deny_count" class="ml-2 text-xs text-warning">{{ view.deny_count }} ACE DENY générée(s)</span>
			<span v-if="view?.unsupported" class="ml-2 text-xs text-danger">pas d'ACL côté NFS</span>
		</summary>
		<div class="mt-2 flex flex-row gap-2">
			<button v-for="t in (['v4', 'v3'] as const)" :key="t" class="btn text-xs py-0.5 px-2"
				:class="proto === t ? 'btn-primary' : 'btn-secondary'" @click="proto = t">
				{{ t === 'v4' ? 'NFSv4.1 (ACL traduites par knfsd)' : 'NFSv3 (nfsacl)' }}
			</button>
		</div>

		<!-- NFSv3 : protocole NFSACL -->
		<div v-if="proto === 'v3'" class="mt-2 space-y-2">
			<p class="text-muted">
				En NFSv3, l'ACL POSIX est transmise telle quelle par le protocole NFSACL (fs/nfsd/nfs3acl.c) :
				<span class="font-mono">getfacl</span> / <span class="font-mono">setfacl</span> côté client voient les
				mêmes entrées que le serveur. Seule différence : les identifiants circulent en numérique et le client
				les affiche avec SES comptes. En NFSv4.1, la même ACL devient une liste d'ACE (onglet NFSv4.1),
				avec éventuellement des ACE DENY générées.
			</p>
			<div v-if="v3?.error" class="text-danger">{{ v3.error }}</div>
			<template v-else-if="v3">
				<label class="flex items-center gap-2 text-default">
					<input type="checkbox" v-model="v3Numeric" class="input-checkbox" />
					identifiants numériques (client sans les mêmes comptes)
				</label>
				<pre class="font-mono text-xs rounded bg-accent p-2 text-default whitespace-pre-wrap">{{ (v3Numeric ? v3.numeric_text : v3.text)?.join('\n') }}</pre>
				<div class="text-xs" :class="v3.over_limit ? 'text-danger' : 'text-muted'">
					Entrées : accès {{ v3.entries_access }}, défaut {{ v3.entries_default }} — limite NFS_ACL_MAX_ENTRIES {{ v3.limit }} par ACL
				</div>
				<ul v-if="v3.notes?.length" class="list-disc pl-5 text-muted">
					<li v-for="n in v3.notes" :key="n">{{ n }}</li>
				</ul>
			</template>
		</div>

		<div v-else class="mt-2 space-y-3">
			<p class="text-muted">
				OpenZFS sous Linux stocke des ACL POSIX ; le serveur NFS du noyau (knfsd) les présente aux clients
				NFSv4 sous forme d'ACL NFSv4 et retraduit en POSIX celles qu'ils posent avec
				<span class="font-mono">nfs4_setfacl</span> (fs/nfsd/nfs4acl.c).
			</p>
			<div v-if="view?.error" class="text-danger">{{ view.error }}</div>
			<div v-else-if="view?.unsupported" class="rounded border border-default p-2 text-danger">{{ view.message }}</div>
			<template v-else-if="view">
				<div class="flex flex-row flex-wrap gap-4 items-center">
					<label class="flex items-center gap-2 text-default">
						<input type="radio" :value="false" v-model="numeric" class="input-checkbox" />
						noms <span class="font-mono">user@{{ view.idmap?.domain }}</span> (sec=krb5*, idmapping actif)
					</label>
					<label class="flex items-center gap-2 text-default">
						<input type="radio" :value="true" v-model="numeric" class="input-checkbox" />
						identifiants numériques (sec=sys, nfs4_disable_idmapping=Y)
					</label>
				</div>
				<pre class="font-mono text-xs rounded bg-accent p-2 text-default whitespace-pre-wrap">{{ (numeric ? view.numeric_text : view.text)?.join('\n') }}</pre>
				<div class="text-xs text-muted">
					Domaine NFSv4 : <span class="font-mono">{{ view.idmap?.domain }}</span> ({{ view.idmap?.domain_source }}) —
					nfs4_disable_idmapping :
					<span class="font-mono">{{ view.idmap?.disable_idmapping === null ? 'nfsd non chargé' : view.idmap?.disable_idmapping ? 'Y' : 'N' }}</span>
				</div>
				<ul v-if="view.notes?.length" class="list-disc pl-5 text-warning">
					<li v-for="n in view.notes" :key="n">{{ n }}</li>
				</ul>
				<details class="text-xs text-muted">
					<summary class="cursor-pointer">Lire une ACE</summary>
					<p class="mt-1">
						Format <span class="font-mono">type:drapeaux:principal:droits</span>. Type A = autoriser, D = refuser.
						Drapeaux : f/d = hérité par fichiers/dossiers, i = héritage seulement (ACL par défaut POSIX),
						g = principal de type groupe. Droits : r lecture, w écriture, a ajout, D suppression d'enfant,
						x exécution, t/T lire/écrire les attributs, c/C lire/écrire l'ACL, y synchronize.
						Les ACE sont évaluées dans l'ordre : un DENY placé avant un ALLOW l'emporte.
					</p>
				</details>
			</template>

			<div class="border-t border-default pt-3 space-y-2">
				<div class="font-medium text-default">Tester une ACL nfs4_setfacl</div>
				<textarea v-model="testAcl" rows="4" class="input-textlike bg-default w-full font-mono text-xs"
					placeholder="A::OWNER@:rwaDxtTcCy&#10;A::GROUP@:rxtcy&#10;A:g:equipe@domaine:rwaDx&#10;A::EVERYONE@:tcy&#10;A:fdi:OWNER@:rwaDx"></textarea>
				<div class="flex flex-row flex-wrap gap-3 items-center">
					<label class="flex items-center gap-2 text-default">
						<input type="checkbox" v-model="asDir" class="input-checkbox" /> cible : dossier
					</label>
					<label class="flex items-center gap-2 text-default" title="nfs4_setfacl retire lui-même héritage et D sur un fichier ; un client Windows / macOS envoie l'ACE telle quelle">
						<input type="checkbox" v-model="otherClient" class="input-checkbox" /> client autre que nfs4_setfacl
					</label>
					<button class="btn btn-secondary" :disabled="busy || !testAcl.trim()" @click="runTest">Tester</button>
					<button class="btn btn-secondary" :disabled="!currentText.length" @click="testAcl = currentText.join('\n')">Partir de l'ACL actuelle</button>
				</div>
				<div v-if="result" class="rounded border border-default p-2 space-y-1">
					<div :class="result.representable ? 'text-success' : 'text-danger'">
						{{ result.representable ? 'Représentable : knfsd l\'accepte' : 'Refusée par knfsd' }}
					</div>
					<div v-if="result.error" class="text-danger">{{ result.error }}</div>
					<template v-if="result.representable">
						<div class="text-default">ACL POSIX stockée (mode résultant <span class="font-mono">{{ result.mode }}</span>) :</div>
						<pre class="font-mono text-xs text-default">{{ fmt(result.access) }}<template v-if="result.default?.length">{{ '\n' + fmt(result.default, 'default:') }}</template></pre>
						<div v-if="result.default_unchanged" class="text-warning">
							ACL par défaut inchangée (aucune ACE héritable envoyée)<template v-if="result.current_default?.length"> :</template>
						</div>
						<pre v-if="result.default_unchanged && result.current_default?.length" class="font-mono text-xs text-default">{{ fmt(result.current_default, 'default:') }}</pre>
						<div class="text-default">Relue ensuite par le client :</div>
						<pre class="font-mono text-xs text-default">{{ result.readback?.join('\n') }}</pre>
					</template>
					<ul v-if="result.notes?.length" class="list-disc pl-5 text-warning">
						<li v-for="n in result.notes" :key="n">{{ n }}</li>
					</ul>
				</div>
			</div>
		</div>
	</details>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { pushNotification, Notification } from '@45drives/houston-common-ui';
import { type Nfs4View, type Nfs3View, type Nfs4TranslateResult, type AclEntry, nfs4Translate, prefersNumeric } from '../../composables/permissions';

const props = defineProps<{ view: Nfs4View | null; v3?: Nfs3View | null; path: string; isDir: boolean; open?: boolean }>();

// nfs4_disable_idmapping vaut Y par défaut : en sec=sys le client voit des identifiants numériques
const numeric = ref(prefersNumeric(props.view?.idmap));
const v3Numeric = ref(false);
const proto = ref<'v4' | 'v3'>('v4');
const currentText = computed(() => (numeric.value ? props.view?.numeric_text : props.view?.text) ?? []);
const testAcl = ref('');
const asDir = ref(props.isDir);
const otherClient = ref(false);
const busy = ref(false);
const result = ref<Nfs4TranslateResult | null>(null);

watch(() => [props.path, props.isDir], () => {
	asDir.value = props.isDir;
	result.value = null;
});
watch(() => props.view?.idmap?.disable_idmapping, () => {
	numeric.value = prefersNumeric(props.view?.idmap);
});

function fmt(entries: AclEntry[] | undefined, prefix = '') {
	return (entries ?? []).map((e) => `${prefix}${e.tag}:${e.qualifier}:${e.perms}`).join('\n');
}

async function runTest() {
	busy.value = true;
	try {
		result.value = await nfs4Translate({ acl: testAcl.value, path: props.path, is_dir: asDir.value, client: otherClient.value ? 'autre' : 'nfs4_setfacl' });
	} catch (e: any) {
		pushNotification(new Notification('Test impossible', e.message, 'error', 6000));
	} finally {
		busy.value = false;
	}
}
</script>
