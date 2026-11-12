<template>
	<div v-if="plan" class="mt-3 rounded-md border border-default p-3 text-sm">
		<div class="flex flex-row flex-wrap gap-4 items-baseline">
			<span class="font-semibold text-default">
				{{ plan.dry_run ? 'Simulation' : 'Appliqué' }} : {{ plan.count }} changement(s)
			</span>
			<span v-if="plan.error_count" class="text-danger">{{ plan.error_count }} erreur(s)</span>
			<span v-if="plan.missing" class="text-muted">{{ plan.missing }} chemin(s) absent(s) ignoré(s)</span>
			<span v-if="plan.backup" class="text-success">Sauvegarde : {{ plan.backup.id }}</span>
		</div>
		<div v-if="plan.commands?.length" class="mt-2">
			<div class="text-muted">Commandes</div>
			<pre class="font-mono text-xs whitespace-pre-wrap text-default">{{ plan.commands.join('\n') }}</pre>
		</div>
		<details v-if="plan.sample?.length" class="mt-2" :open="plan.dry_run">
			<summary class="cursor-pointer text-default">
				Échantillon ({{ plan.sample.length }}{{ plan.count > plan.sample.length ? ' sur ' + plan.count : '' }})
			</summary>
			<table class="mt-1 w-full text-xs">
				<tbody>
					<tr v-for="s in plan.sample" :key="s.path + s.change" class="border-t border-default">
						<td class="font-mono py-0.5 pr-2 break-all text-default">{{ s.path }}</td>
						<td class="text-muted">{{ s.change }}</td>
					</tr>
				</tbody>
			</table>
		</details>
		<details v-if="plan.errors?.length" class="mt-2" open>
			<summary class="cursor-pointer text-danger">Erreurs</summary>
			<ul class="text-xs font-mono">
				<li v-for="(e, i) in plan.errors" :key="i" class="break-all text-danger">{{ e.path }} — {{ e.error }}</li>
			</ul>
		</details>
	</div>
</template>

<script setup lang="ts">
import type { PlanResult } from '../../composables/permissions';
defineProps<{ plan: PlanResult | null }>();
</script>
