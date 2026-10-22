export {
	type AuthClientOptions,
	createAuthClient,
	isUnavailableError,
	type UnavailableReason,
	unavailableError,
} from "./client.js";
export {
	type AuthHandler,
	type AuthHandlerOptions,
	createAuthHandler,
} from "./handler.js";
export { SERVICE_ROUTES, type ServiceSurface } from "./protocol.js";
