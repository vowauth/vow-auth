export type FlowNode = {
	readonly id: string;
	readonly kind: string;
	readonly title: string;
	readonly source?: { readonly file: string; readonly line: number };
	readonly jump?: { readonly flow: string; readonly node: string };
};

export type FlowEdge = {
	readonly from: string;
	readonly to: string;
	readonly label: string;
	readonly kind: string;
};

export type Flow = {
	readonly id: string;
	readonly group: string;
	readonly title: string;
	readonly nodes: readonly FlowNode[];
	readonly edges: readonly FlowEdge[];
};

export type FlowData = {
	readonly groups: readonly string[];
	readonly events: readonly string[];
	readonly ports: readonly string[];
	readonly flows: readonly Flow[];
};

export function buildFlowData(): {
	readonly data: FlowData;
	readonly problems: readonly string[];
};

export function serialize(data: FlowData): string;
