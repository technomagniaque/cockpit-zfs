<template>
	<div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
		<label v-if="showRecursive" class="flex items-center gap-2 text-default">
			<input type="checkbox" v-model="model.recursive" class="input-checkbox" />
			Récursif
		</label>
		<label class="flex items-center gap-2 text-default">
			<input type="checkbox" v-model="model.include_root" class="input-checkbox" />
			Inclure le chemin racine
		</label>
		<label class="flex items-center gap-2 text-default" title="Par défaut, les datasets enfants (autre st_dev) sont ignorés">
			<input type="checkbox" v-model="model.cross_datasets" class="input-checkbox" />
			Traverser les datasets enfants
		</label>
		<div>
			<label class="block text-default">Cible</label>
			<select v-model="model.types" class="input-textlike bg-default w-full">
				<option value="all">Fichiers et dossiers</option>
				<option value="dirs">Dossiers seulement</option>
				<option value="files">Fichiers seulement</option>
			</select>
		</div>
		<div>
			<label class="block text-default">Profondeur max. (vide = illimitée)</label>
			<input type="number" min="0" v-model.number="depth" class="input-textlike bg-default w-full" />
		</div>
		<div></div>
		<div class="md:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-3">
			<div>
				<label class="block text-default">Inclure (motifs glob, un par ligne)</label>
				<textarea v-model="includeText" rows="2" class="input-textlike bg-default w-full font-mono" placeholder="*.docx&#10;Projets/*"></textarea>
			</div>
			<div>
				<label class="block text-default">Exclure (élague les dossiers correspondants)</label>
				<textarea v-model="excludeText" rows="2" class="input-textlike bg-default w-full font-mono" placeholder=".snapshots&#10;*.tmp"></textarea>
			</div>
		</div>
	</div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { WalkOptions } from '../../composables/permissions';

// L'objet passé en modelValue est réactif côté parent : on modifie ses champs directement.
const props = withDefaults(defineProps<{ modelValue: WalkOptions; showRecursive?: boolean }>(), { showRecursive: true });
const model = computed(() => props.modelValue);

const lines = (s: string) => s.split('\n').map((l) => l.trim()).filter(Boolean);

const includeText = computed({
	get: () => (model.value.include ?? []).join('\n'),
	set: (v: string) => (model.value.include = lines(v)),
});
const excludeText = computed({
	get: () => (model.value.exclude ?? []).join('\n'),
	set: (v: string) => (model.value.exclude = lines(v)),
});
const depth = computed({
	get: () => model.value.max_depth ?? '',
	set: (v: number | string) => (model.value.max_depth = v === '' || v === null ? null : Number(v)),
});
</script>
