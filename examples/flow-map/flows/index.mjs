import { outbox, serviceClient, serviceServer } from "./async-and-service.mjs";
import { emailLink, identity, sealer, tokens } from "./data.mjs";
import { GROUPS } from "./dsl.mjs";
import { authorizeFlow, meter, transport } from "./protection.mjs";
import {
	agentDelegate,
	agentVerify,
	revoke,
	sessionVerify,
} from "./sessions.mjs";
import { signIn, signInStepUp } from "./sign-in.mjs";
import { doctor, map, startup } from "./tools-and-map.mjs";

export { GROUPS };

export const flows = [
	map,
	signIn,
	signInStepUp,
	sessionVerify,
	revoke,
	agentDelegate,
	agentVerify,
	identity,
	tokens,
	emailLink,
	sealer,
	meter,
	authorizeFlow,
	transport,
	outbox,
	serviceServer,
	serviceClient,
	startup,
	doctor,
];
