import { useState } from 'react';
import { svcColor, svcDisplayName, svcLogoUrl } from '../utils/services';

interface Props {
  service: string;
  size?: number;
  showUploadDot?: boolean;
  className?: string;
}

export default function SvcLogo({ service, size = 20, showUploadDot, className }: Props) {
  const [failed, setFailed] = useState(false);
  const color = svcColor(service);
  const letter = svcDisplayName(service).charAt(0);

  if (failed) {
    return (
      <span className={`relative inline-flex ${className || ''}`}>
        <span
          className="inline-flex items-center justify-center rounded text-white text-[10px] font-bold flex-shrink-0"
          style={{ background: color, width: size, height: size }}
        >
          {letter}
        </span>
        {showUploadDot && <UploadDot />}
      </span>
    );
  }

  return (
    <span className={`relative inline-flex ${className || ''}`}>
      <img
        src={svcLogoUrl(service)}
        alt={service}
        className="rounded flex-shrink-0"
        style={{ width: size, height: size }}
        onError={() => setFailed(true)}
      />
      {showUploadDot && <UploadDot />}
    </span>
  );
}

function UploadDot() {
  return (
    <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-red-500 border border-white dark:border-[#0B0C10]" />
  );
}
