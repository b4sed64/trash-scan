// The Trash Scan mark. The raccoon emoji reads clearly at every size and already
// wears the bandit mask; the low-opacity watermark treatment is done in CSS.

export function Raccoon({ size = 24 }: { size?: number }) {
  return (
    <span
      className="raccoon-emoji"
      style={{ fontSize: size, lineHeight: 1 }}
      role="img"
      aria-label="Trash Scan"
    >
      🦝
    </span>
  );
}
