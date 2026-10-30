import React, { useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import { Btn, Note, errorText } from "./ui";

type Mode = "idle" | "camera" | "screen";

interface Props {
  /** What the user should point at, e.g. "the holder key QR on Prime". */
  hint: string;
  onResult: (text: string) => void;
}

/**
 * Reads a QR from the webcam (Prime held up to the camera), from a shared screen or window
 * (the Prime simulator), or from pasted / uploaded JSON. Decoding is local; nothing is uploaded.
 */
export const QrScanner: React.FC<Props> = ({ hint, onResult }) => {
  const [mode, setMode] = useState<Mode>("idle");
  const [error, setError] = useState("");
  const [paste, setPaste] = useState("");
  const video = useRef<HTMLVideoElement>(null);
  const stream = useRef<MediaStream | null>(null);
  const frame = useRef<number>(0);

  const stop = () => {
    cancelAnimationFrame(frame.current);
    stream.current?.getTracks().forEach((t) => t.stop());
    stream.current = null;
    setMode("idle");
  };

  useEffect(() => stop, []);

  const start = async (next: "camera" | "screen") => {
    setError("");
    try {
      const media =
        next === "camera"
          ? await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } })
          : await navigator.mediaDevices.getDisplayMedia({ video: true });
      stream.current = media;
      media.getVideoTracks()[0]?.addEventListener("ended", stop);
      setMode(next);
      const el = video.current!;
      el.srcObject = media;
      await el.play();
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
      const tick = () => {
        if (el.readyState >= el.HAVE_ENOUGH_DATA && el.videoWidth) {
          const scale = Math.min(1, 1600 / el.videoWidth);
          canvas.width = Math.round(el.videoWidth * scale);
          canvas.height = Math.round(el.videoHeight * scale);
          ctx.drawImage(el, 0, 0, canvas.width, canvas.height);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
          if (code && code.binaryData.length) {
            stop();
            onResult(new TextDecoder().decode(Uint8Array.from(code.binaryData)));
            return;
          }
        }
        frame.current = requestAnimationFrame(tick);
      };
      frame.current = requestAnimationFrame(tick);
    } catch (e) {
      stop();
      setError(next === "camera" ? `Camera unavailable: ${errorText(e)}` : `Screen capture cancelled or blocked: ${errorText(e)}`);
    }
  };

  const readFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > 64 * 1024) return setError("File too large for a PrimeID payload");
    onResult(await file.text());
  };

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">Scan {hint}.</p>
      <div className={mode === "idle" ? "hidden" : "relative rounded-xl overflow-hidden border border-foundation-border bg-black"}>
        <video ref={video} muted playsInline className="w-full max-h-80 object-contain" />
        <div className="absolute bottom-2 inset-x-0 text-center text-[11px] text-slate-300">Looking for a QR code...</div>
      </div>
      <div className="flex gap-2 flex-wrap">
        {mode === "idle" ? (
          <>
            <Btn onClick={() => start("camera")}>Scan with camera</Btn>
            <Btn variant="secondary" onClick={() => start("screen")} title="Pick the Prime simulator window">Scan a window</Btn>
            <label className="px-4 py-2 rounded-xl text-sm font-semibold bg-[#181D26] border border-[#2B3342] text-slate-200 hover:bg-[#202733] cursor-pointer">
              Open .json
              <input type="file" accept=".json,application/json" className="hidden" onChange={(e) => readFile(e.target.files?.[0])} />
            </label>
          </>
        ) : (
          <Btn variant="secondary" onClick={stop}>Stop</Btn>
        )}
      </div>
      <details className="text-xs text-slate-400">
        <summary className="cursor-pointer">Paste JSON instead</summary>
        <textarea
          value={paste}
          onChange={(e) => setPaste(e.target.value)}
          rows={4}
          className="mt-2 w-full bg-[#07090C] border border-foundation-border rounded-lg p-2 font-mono text-[11px] text-slate-200"
        />
        <Btn variant="secondary" className="mt-2" disabled={!paste.trim()} onClick={() => { onResult(paste.trim()); setPaste(""); }}>
          Use pasted text
        </Btn>
      </details>
      {error && <Note tone="bad">{error}</Note>}
    </div>
  );
};
