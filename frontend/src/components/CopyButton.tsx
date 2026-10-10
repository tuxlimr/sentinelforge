import { useState } from "react";
import { copyText } from "../format";
import { Icon } from "./Icon";

/** Copies text to the clipboard and briefly confirms. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await copyText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button className="btn btn-sm btn-ghost" onClick={copy}>
      <Icon name={copied ? "check" : "content_copy"} size={14} />
      {copied ? "Copied" : label}
    </button>
  );
}
