import { legacy } from '@45drives/houston-common-lib';
// @ts-ignore
import permissions_script from "../scripts/zfs-permissions.py?raw";

const { errorString, useSpawn } = legacy;

export type AclTag = 'user' | 'group' | 'mask' | 'other';

export interface AclEntry {
	tag: AclTag;
	qualifier: string;
	perms: string;
}

export interface PosixAcl {
	owner: string | null;
	group: string | null;
	flags: string;
	access: AclEntry[];
	default: AclEntry[];
}

export interface PathInfo {
	path: string;
	type: 'dir' | 'file' | 'link' | 'other';
	mode: string;
	symbolic: string;
	uid: number;
	owner: string | null;
	gid: number;
	group: string | null;
	setgid: boolean;
	sticky: boolean;
	xattrs: string[];
	has_ntacl: boolean;
	has_posix_acl: boolean;
	immutable: boolean;
	append_only: boolean;
}

export interface InspectResult {
	path: string;
	dataset: string;
	mountpoint: string;
	props: Record<string, { value: string; source: string }>;
	info: PathInfo;
	acl: PosixAcl | null;
	acl_error: string | null;
	children: PathInfo[];
	warnings: string[];
	acl_mode: 'posix' | 'off' | 'nfsv4';
}

export interface WalkOptions {
	recursive?: boolean;
	include_root?: boolean;
	cross_datasets?: boolean;
	max_depth?: number | null;
	include?: string[];
	exclude?: string[];
	types?: 'all' | 'files' | 'dirs';
}

export interface PlanResult {
	dry_run: boolean;
	count: number;
	sample: { path: string; change: string }[];
	commands: string[];
	errors: { path: string; error: string }[];
	error_count: number;
	backup?: BackupMeta | null;
	missing?: number;
	[key: string]: unknown;
}

export interface BackupMeta {
	id: string;
	path: string;
	dataset: string;
	reason: string;
	created: number;
	entries: number;
	size: number;
}

export interface AuditResult {
	path: string;
	dataset: string;
	acl_mode: string;
	total: number;
	files: number;
	dirs: number;
	truncated: boolean;
	counts: Record<string, number>;
	findings: Record<string, string[]>;
	owners: { id: number; name: string | null; count: number }[];
	groups: { id: number; name: string | null; count: number }[];
	modes: { mode: string; kind: string; count: number }[];
}

export interface DelegationWho {
	type: 'user' | 'group' | 'everyone';
	who: string;
	perms: string[];
}

export interface DelegationEntry {
	dataset: string;
	sets: { name: string; perms: string[] }[];
	create: { perms: string[] }[];
	local: DelegationWho[];
	descendent: DelegationWho[];
	both: DelegationWho[];
}

export type ResetMethod =
	| 'unix-mode' | 'strip-acl' | 'acl-template' | 'inherit-parent' | 'mirror-reference'
	| 'from-snapshot' | 'from-backup' | 'clear-ntacl' | 'orphans' | 'takeown' | 'chattr-clear';

export class PermissionsError extends Error {
	trace?: string;
	constructor(message: string, trace?: string) {
		super(message);
		this.trace = trace;
	}
}

/** Exécute une commande du backend Python en root et renvoie le JSON décodé. */
export async function permissionsCall<T = any>(command: string, params: object = {}): Promise<T> {
	let stdout: string;
	try {
		const state = useSpawn(
			['/usr/bin/env', 'python3', '-c', permissions_script, command, JSON.stringify(params)],
			{ superuser: 'try' },
		);
		stdout = (await state.promise()).stdout ?? '';
	} catch (state) {
		throw new PermissionsError(errorString(state));
	}
	let data: any;
	try {
		data = JSON.parse(stdout);
	} catch {
		throw new PermissionsError(`Réponse illisible du backend : ${stdout.slice(0, 300)}`);
	}
	if (!data.ok) {
		throw new PermissionsError(data.error ?? 'Erreur inconnue', data.trace);
	}
	return data as T;
}

export const inspectPath = (path: string) => permissionsCall<InspectResult>('inspect', { path });
export const auditPath = (path: string, opts: WalkOptions & { max_entries?: number; check_flags?: boolean } = {}) =>
	permissionsCall<AuditResult>('audit', { path, ...opts });
export const setAcl = (params: { path: string; action: 'set' | 'modify' | 'remove' | 'remove-default'; access: AclEntry[]; default: AclEntry[]; dry_run: boolean; files_conditional_x?: boolean; backup?: boolean } & WalkOptions) =>
	permissionsCall<PlanResult>('set-acl', params);
export const resetPermissions = (method: ResetMethod, path: string, options: Record<string, unknown>, dryRun: boolean) =>
	permissionsCall<PlanResult>('reset', { ...options, method, path, dry_run: dryRun });
export const listBackups = () => permissionsCall<{ backups: BackupMeta[] }>('backups');
export const deleteBackup = (id: string) => permissionsCall('delete-backup', { id });
export const getDelegation = (dataset: string) =>
	permissionsCall<{ dataset: string; entries: DelegationEntry[]; known_perms: string[]; raw: string }>('delegation', { dataset });
export const delegate = (params: { dataset: string; op: 'allow' | 'unallow'; kind: 'user' | 'group' | 'everyone' | 'create' | 'set'; who?: string; scope?: 'local' | 'descendent' | 'both'; perms: string[]; recursive?: boolean; dry_run?: boolean }) =>
	permissionsCall<{ dry_run: boolean; command: string }>('delegate', params);
export const applyPreset = (dataset: string, preset: string, dryRun: boolean) =>
	permissionsCall<{ dry_run: boolean; changes: { prop: string; from: string; to: string; note?: string }[]; commands: string[]; notes: string[]; errors?: { command: string; error: string }[] }>('preset', { dataset, preset, dry_run: dryRun });
export const getMethods = () =>
	permissionsCall<{ methods: Record<ResetMethod, string>; presets: Record<string, string> }>('methods');

/** Snapshots directs d'un dataset (sources pour la restauration des permissions). */
export async function listDatasetSnapshots(dataset: string): Promise<string[]> {
	try {
		const state = useSpawn(['zfs', 'list', '-H', '-t', 'snapshot', '-o', 'name', '-s', 'creation', '-d', '1', dataset], { superuser: 'try' });
		const out = (await state.promise()).stdout ?? '';
		return out.split('\n').map((l: string) => l.trim()).filter(Boolean).reverse();
	} catch (state) {
		console.error(errorString(state));
		return [];
	}
}

/** Convertit "rwx" ↔ cases à cocher. */
export function permsToFlags(perms: string) {
	return { r: perms[0] === 'r', w: perms[1] === 'w', x: perms[2] === 'x' || perms[2] === 'X' };
}

export function flagsToPerms(f: { r: boolean; w: boolean; x: boolean }) {
	return `${f.r ? 'r' : '-'}${f.w ? 'w' : '-'}${f.x ? 'x' : '-'}`;
}

/** Libellé lisible d'une entrée d'ACL. */
export function aclEntryLabel(e: AclEntry) {
	switch (e.tag) {
		case 'user': return e.qualifier ? `Utilisateur ${e.qualifier}` : 'Propriétaire';
		case 'group': return e.qualifier ? `Groupe ${e.qualifier}` : 'Groupe propriétaire';
		case 'mask': return 'Masque (droits max. des entrées nommées et du groupe)';
		case 'other': return 'Autres';
	}
}
