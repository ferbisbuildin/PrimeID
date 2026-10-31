import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import { Copy, Check, Eye, EyeOff, Radio } from "lucide-react";

interface QrCodeDisplayProps {
  data: string | object;
  title?: string;
  subtitle?: string;
  size?: number;
  onBeam?: () => void;
  beamLabel?: string;
  showRawToggle?: boolean;
}

export const QrCodeDisplay: React.FC<QrCodeDisplayProps> = ({
  data,
  title,
  subtitle,
  size = 240,
  onBeam,
  beamLabel = "Beam to Device (Air-Gap Bridge)",
  showRawToggle = true,
}) => {
  const [svgString, setSvgString] = useState<string>("");
  const [copied, setCopied] = useState<boolean>(false);
  const [showRaw, setShowRaw] = useState<boolean>(false);

  const serializedData = typeof data === "string" ? data : JSON.stringify(data);

  useEffect(() => {
    QRCode.toString(
      serializedData,
      {
        type: "svg",
        margin: 2,
        color: {
          dark: "#000000",
          light: "#FFFFFF",
        },
        errorCorrectionLevel: "M",
      },
      (err, svg) => {
        if (!err && svg) {
          setSvgString(svg);
        } else {
          console.error("QR generation error:", err);
        }
      }
    );
  }, [serializedData]);

  const handleCopy = () => {
    navigator.clipboard.writeText(serializedData);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex flex-col items-center bg-[#0D1016] border border-[#232936] rounded-2xl p-5 shadow-oled">
      {title && (
        <h3 className="text-sm font-semibold tracking-wide text-amber-300 uppercase mb-1 font-mono">
          {title}
        </h3>
      )}
      {subtitle && <p className="text-xs text-slate-400 text-center mb-4">{subtitle}</p>}

      {/* QR Code Frame */}
      <div className="p-3 bg-white rounded-xl shadow-lg border-2 border-[#D4AF37]/40 flex items-center justify-center">
        {svgString ? (
          <div
            className="w-full h-full flex items-center justify-center"
            style={{ width: `${size}px`, height: `${size}px` }}
            dangerouslySetInnerHTML={{ __html: svgString }}
          />
        ) : (
          <div
            className="flex items-center justify-center bg-slate-100 text-slate-500 font-mono text-xs"
            style={{ width: `${size}px`, height: `${size}px` }}
          >
            Generating QR...
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="w-full flex flex-col gap-2 mt-4">
        {onBeam && (
          <button
            onClick={onBeam}
            className="flex items-center justify-center gap-2 py-2.5 px-4 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-semibold text-xs rounded-xl shadow-md transition-all active:scale-98"
          >
            <Radio className="w-4 h-4 animate-pulse text-slate-950" />
            {beamLabel}
          </button>
        )}

        <div className="flex items-center justify-between gap-2">
          <button
            onClick={handleCopy}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 px-3 bg-[#181D26] hover:bg-[#202733] border border-[#2B3342] text-slate-300 hover:text-white rounded-xl text-xs transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-mono">Copied Payload</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Raw JSON</span>
              </>
            )}
          </button>

          {showRawToggle && (
            <button
              onClick={() => setShowRaw(!showRaw)}
              className="flex items-center justify-center gap-1.5 py-2 px-3 bg-[#181D26] hover:bg-[#202733] border border-[#2B3342] text-slate-300 hover:text-white rounded-xl text-xs transition-colors"
              title="Inspect raw cryptographic JSON"
            >
              {showRaw ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              <span>{showRaw ? "Hide" : "Inspect"}</span>
            </button>
          )}
        </div>
      </div>

      {/* Raw Payload Inspector */}
      {showRaw && (
        <div className="w-full mt-3 p-3 bg-[#07090C] border border-[#232936] rounded-xl text-[11px] font-mono text-slate-300 max-h-48 overflow-y-auto">
          <pre className="whitespace-pre-wrap break-all">{serializedData}</pre>
        </div>
      )}
    </div>
  );
};
