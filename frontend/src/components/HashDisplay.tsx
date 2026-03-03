import type { Hashes } from "@/types/analysis";

interface HashDisplayProps {
  hashes: Hashes;
}

function CopyButton({ value }: { value: string }) {
  const handleCopy = () => {
    navigator.clipboard.writeText(value);
  };

  return (
    <button
      onClick={handleCopy}
      title="Copy to clipboard"
      className="ml-2 shrink-0 rounded p-1 text-gray-500 hover:bg-gray-700 hover:text-cyan-400 transition-colors"
    >
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" />
      </svg>
    </button>
  );
}

export default function HashDisplay({ hashes }: HashDisplayProps) {
  const items: { label: string; value: string; color: string }[] = [
    { label: "MD5", value: hashes.md5, color: "text-orange-400" },
    { label: "SHA-1", value: hashes.sha1, color: "text-blue-400" },
    { label: "SHA-256", value: hashes.sha256, color: "text-emerald-400" },
  ];

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
        File Hashes
      </h3>
      {items.map((h) => (
        <div
          key={h.label}
          className="rounded-lg bg-gray-900/80 p-3 ring-1 ring-gray-800"
        >
          <div className="mb-1 flex items-center justify-between">
            <span className={`text-xs font-bold ${h.color}`}>{h.label}</span>
            <CopyButton value={h.value} />
          </div>
          <code className="block break-all text-xs text-gray-300 font-mono">
            {h.value}
          </code>
        </div>
      ))}
    </div>
  );
}
