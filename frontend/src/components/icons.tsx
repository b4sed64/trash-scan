// Small inline glyphs for the scan controls. They inherit `currentColor` and
// size to the surrounding text.

type Props = { size?: number };

export function PlayIcon({ size = 15 }: Props) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M4 2.5v11a1 1 0 0 0 1.54.84l8.5-5.5a1 1 0 0 0 0-1.68l-8.5-5.5A1 1 0 0 0 4 2.5Z" />
    </svg>
  );
}

export function PauseIcon({ size = 15 }: Props) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <rect x="3.5" y="2.5" width="3.5" height="11" rx="1" />
      <rect x="9" y="2.5" width="3.5" height="11" rx="1" />
    </svg>
  );
}

export function StopIcon({ size = 15 }: Props) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <rect x="3" y="3" width="10" height="10" rx="1.5" />
    </svg>
  );
}
