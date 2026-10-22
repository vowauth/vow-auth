import { goodOptions, nonAtomicTokenStore } from "../support.js";

export default async () => ({
	options: { ...goodOptions(), tokenStore: nonAtomicTokenStore() },
});
