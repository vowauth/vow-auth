import type {
	GrantStore,
	RevocationLevel,
	SessionReading,
	StoredGrant,
} from "@vow-auth/core";

const marks = (level: RevocationLevel, grant: StoredGrant): boolean => {
	switch (level.scope) {
		case "session":
			return grant.id === level.id || grant.sessionId === level.id;
		case "device":
			return grant.device === level.id;
		case "account":
			return (
				grant.accountId === level.id &&
				(grant.kind === "session" || grant.sessionId !== undefined)
			);
		case "subject":
			return grant.tenant === level.tenant && grant.subjectId === level.id;
		case "tenant":
			return grant.tenant === level.tenant;
		case "agent":
			return (
				grant.kind === "agent" &&
				grant.tenant === level.tenant &&
				grant.agent === level.id
			);
		case "delegation":
			return grant.kind === "agent" && grant.id === level.id;
	}
};

/**
 * In-process grant store for tests and single-instance development, with the
 * same answers as the Postgres store: a session's entry into a tenant is the
 * live one when there is one and else the latest revoked one, a revocation
 * marks its level and everything bound to it, and the device is kept on
 * everything bound to a session, so revoking a device reaches it all. Time is
 * `Date.now`. Every method runs to its end before another starts, which makes
 * each one atomic.
 */
export function createMemoryGrantStore(): GrantStore {
	const grants = new Map<string, StoredGrant>();
	const byHash = new Map<string, string>();

	const put = (grant: StoredGrant): void => {
		grants.set(grant.id, grant);

		if (grant.tokenHash !== undefined) {
			byHash.set(grant.tokenHash, grant.id);
		}
	};

	const taken = (grant: StoredGrant): boolean =>
		grants.has(grant.id) ||
		(grant.tokenHash !== undefined && byHash.has(grant.tokenHash));

	const entriesOf = (sessionId: string, tenant: string): StoredGrant[] =>
		Array.from(grants.values()).filter(
			(grant) =>
				grant.kind === "tenant" &&
				grant.sessionId === sessionId &&
				grant.tenant === tenant,
		);

	const byToken = (tokenHash: string): StoredGrant | undefined => {
		const id = byHash.get(tokenHash);

		return id === undefined ? undefined : grants.get(id);
	};

	const readingOf = (
		session: StoredGrant | undefined,
		tenant: string | undefined,
	): SessionReading | undefined => {
		if (session === undefined) {
			return undefined;
		}

		const entries = tenant === undefined ? [] : entriesOf(session.id, tenant);
		const entry =
			entries.find((candidate) => !candidate.revoked) ?? entries.at(-1);

		return { session, entry, now: Date.now() };
	};

	return {
		async now() {
			return Date.now();
		},
		async createSession(session, entry) {
			if (taken(session) || taken(entry)) {
				throw new Error("A grant with this id or token exists already");
			}

			put(session);
			put(entry);
		},
		async createGrant(grant) {
			const liveEntry =
				grant.kind === "tenant" &&
				grant.sessionId !== undefined &&
				grant.tenant !== undefined &&
				entriesOf(grant.sessionId, grant.tenant).some(
					(entry) => !entry.revoked,
				);
			const parentMissing =
				grant.parentId !== undefined && !grants.has(grant.parentId);

			if (taken(grant) || liveEntry || parentMissing) {
				return "conflict";
			}

			put(grant);

			return "created";
		},
		async findSession(tokenHash, tenant) {
			return readingOf(byToken(tokenHash), tenant);
		},
		async getSession(id, tenant) {
			const session = grants.get(id);

			return readingOf(
				session?.kind === "session" ? session : undefined,
				tenant,
			);
		},
		async findAgent(tokenHash) {
			const agent = byToken(tokenHash);

			if (agent === undefined) {
				return undefined;
			}

			return {
				agent,
				session:
					agent.sessionId === undefined
						? undefined
						: grants.get(agent.sessionId),
				now: Date.now(),
			};
		},
		async extendSession(id, idleExpiresAtMilliseconds) {
			const session = grants.get(id);

			if (session === undefined) {
				return;
			}

			grants.set(id, {
				...session,
				idleExpiresAtMilliseconds: Math.min(
					Math.max(
						session.idleExpiresAtMilliseconds ?? idleExpiresAtMilliseconds,
						idleExpiresAtMilliseconds,
					),
					session.expiresAtMilliseconds,
				),
			});
		},
		async revoke(level) {
			let marked = 0;

			for (const grant of grants.values()) {
				if (marks(level, grant)) {
					grants.set(grant.id, { ...grant, revoked: true });
					marked += 1;
				}
			}

			return marked;
		},
		async forget(accountId) {
			for (const grant of [...grants.values()]) {
				if (grant.accountId === accountId) {
					grants.delete(grant.id);

					if (grant.tokenHash !== undefined) {
						byHash.delete(grant.tokenHash);
					}
				}
			}
		},
	};
}
