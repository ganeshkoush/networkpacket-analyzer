import { createContext, useContext, type ReactNode } from "react";
import { api as defaultApi, type Api } from "../api/client";

const Ctx = createContext<Api>(defaultApi);

/** Lets pages reach the backend API; tests inject a mock. */
export function ApiProvider({ api, children }: { api?: Api; children: ReactNode }) {
  return <Ctx.Provider value={api ?? defaultApi}>{children}</Ctx.Provider>;
}
export const useApi = (): Api => useContext(Ctx);
