import { AsyncLocalStorage } from "node:async_hooks";

const requestAuth = new AsyncLocalStorage<string>();

export function runWithRequestAuth<T>(token: string, callback: () => T): T {
  return requestAuth.run(token, callback);
}

export function getRequestAuthToken(): string | undefined {
  return requestAuth.getStore();
}
