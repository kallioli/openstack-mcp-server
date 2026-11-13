import { useId } from "react";

/** OpenStack MCP Server mark: three stacked layers (a cloud stack) on a teal to blue tile. */
export function Logo({ size = 34, className }: { size?: number; className?: string }) {
  const gradient = useId();
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 64 64" role="img" aria-label="OpenStack MCP Server">
      <defs>
        <linearGradient id={gradient} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#0FA3A3" />
          <stop offset="1" stopColor="#2563EB" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="16" fill={`url(#${gradient})`} />
      <rect x="14" y="14" width="36" height="9" rx="4.5" fill="#fff" />
      <rect x="14" y="27.5" width="36" height="9" rx="4.5" fill="#fff" fillOpacity="0.82" />
      <rect x="14" y="41" width="36" height="9" rx="4.5" fill="#fff" fillOpacity="0.64" />
      <circle cx="20" cy="18.5" r="2" fill="#2563EB" />
      <circle cx="20" cy="32" r="2" fill="#2563EB" />
      <circle cx="20" cy="45.5" r="2" fill="#2563EB" />
    </svg>
  );
}
