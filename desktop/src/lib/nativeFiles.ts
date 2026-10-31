import { hasNativeDialogs } from "./exportCapture";

export { hasNativeDialogs };
type Filter = { name: string; extensions: string[] };

/** Native "Save as" dialog (desktop app only). Null = cancelled, or no native dialogs (the caller falls back or explains). */
export async function pickSavePath(defaultName: string, filters: Filter[], title = "Save"): Promise<string | null> {
  if (!hasNativeDialogs()) return null;
  const { save } = await import("@tauri-apps/plugin-dialog");
  return (await save({ title, defaultPath: defaultName, filters })) ?? null;
}

/** Native "Open file" dialog (desktop app only). */
export async function pickOpenPath(filters: Filter[], title = "Open"): Promise<string | null> {
  if (!hasNativeDialogs()) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ title, multiple: false, directory: false, filters });
  return typeof r === "string" ? r : null;
}
