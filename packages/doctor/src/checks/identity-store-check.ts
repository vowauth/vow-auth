import { canonicalizeEmail, type IdentityClaims } from "@vow-auth/core";
import type { Check, Finding } from "../finding.js";
import { inParallel, probeId } from "../probe.js";

const PARALLEL_SIGN_INS = 16;
const PROBE_PROVIDER = "doctor";
const PROBE_ADDRESS = "doctor@example.com";

export const identityStoreCheck: Check = {
	id: "identity-store-not-first-wins",
	title:
		"The identity store creates one subject per identity and keeps tenants apart",
	async run({ options }) {
		const store = options.identities;
		const email = canonicalizeEmail(PROBE_ADDRESS);

		if (email === undefined) {
			throw new Error("the probe address must be valid");
		}

		const tenant = probeId("tenant");
		const otherTenant = probeId("tenant");
		const externalId = probeId("external");
		const claims: IdentityClaims = {
			provider: PROBE_PROVIDER,
			externalId,
			email,
			emailVerified: true,
		};
		const results = await inParallel(PARALLEL_SIGN_INS, () =>
			store.createSubject(tenant, claims),
		);
		const subjects = new Set(results.map((result) => result.subjectId));
		const created = results.filter((result) => result.isNew).length;
		const findings: Finding[] = [];

		try {
			if (created !== 1 || subjects.size !== 1) {
				findings.push({
					id: "identity-store-not-first-wins",
					level: "error",
					title: `${PARALLEL_SIGN_INS} parallel sign-ins of one identity created ${created} new subjects (${subjects.size} different ids)`,
					scenario: [
						"Sign in with a new email from two devices at the same moment.",
						`The store creates ${subjects.size} subjects for one identity.`,
						"The sessions belong to different subjects, and one of them is not the subject that later sign-ins and revocations reach: the user cannot revoke it.",
					],
					fix: "Make createSubject and linkIdentity atomic and first-wins: a unique constraint on (tenant, provider, external id) and return the existing owner on conflict. Run identityStoreContract of @vow-auth/store-contracts against the adapter.",
				});
			}

			const crossed =
				(await store.findSubject(otherTenant, PROBE_PROVIDER, externalId)) !==
					undefined ||
				(await store.findSubjectByVerifiedEmail(otherTenant, email)) !==
					undefined;

			if (crossed) {
				findings.push({
					id: "identity-store-crosses-tenants",
					level: "error",
					title: "A lookup in one tenant found a subject of another tenant",
					scenario: [
						"Sign in as a user of tenant A with an email.",
						"Sign in to tenant B with the same email, or the same provider identity.",
						"The store answers with the subject of tenant A, and tenant B gets a session for it.",
					],
					fix: "Put the tenant in every key and in every query of the adapter (A5).",
				});
			}
		} finally {
			for (const subjectId of subjects) {
				await store.deleteSubject(tenant, subjectId);
			}
		}

		return findings;
	},
};
