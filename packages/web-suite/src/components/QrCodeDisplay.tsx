import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import { Btn, Note } from "./ui";

interface Props {
  text: string;
  caption?: string;
  /** Offer a .json download so Prime can import it from USB or internal storage. */
  downloadName?: string;
}

export const QrCodeDisplay: React.FC<Props> = ({ text, caption, downloadName }) => {
  const [svg, setSvg] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    setError("");
    // Low error correction keeps large payloads at a QR version Prime's camera reads reliably.
    QRCode.toString(text, { type: "svg", margin: 2, errorCorrectionLevel: "L" })
      .then(setSvg)
      .catch((e: Error) => {
        setSvg("");
        setError(e.message);
      });
  }, [text]);

  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: downloadName });
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col items-center gap-3">
      {error ? (
        <Note tone="bad">QR could not be generated: {error}</Note>
      ) : (
        <div className="bg-white p-2 rounded-xl w-full max-w-[360px] aspect-square [&>svg]:w-full [&>svg]:h-full" dangerouslySetInnerHTML={{ __html: svg }} />
      )}
      {caption && <p className="text-xs text-slate-400 text-center">{caption}</p>}
      <p className="text-[11px] text-slate-500 font-mono">{new TextEncoder().encode(text).length} bytes</p>
      <div className="flex gap-2 flex-wrap justify-center">
        <Btn variant="secondary" onClick={copy}>{copied ? "Copied" : "Copy JSON"}</Btn>
        {downloadName && <Btn variant="secondary" onClick={download}>Download .json</Btn>}
        <Btn variant="secondary" onClick={() => setShowRaw(!showRaw)}>{showRaw ? "Hide" : "Inspect"}</Btn>
      </div>
      {showRaw && (
        <pre className="w-full text-[11px] font-mono text-slate-300 bg-[#07090C] border border-foundation-border rounded-lg p-3 max-h-56 overflow-auto whitespace-pre-wrap break-all">
          {JSON.stringify(JSON.parse(text), null, 2)}
        </pre>
      )}
    </div>
  );
};
