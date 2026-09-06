// The Trash Scan mark: a raccoon bandit mask. Monochrome, uses currentColor,
// eye holes are true cut-outs (fill-rule evenodd) so it reads on any background.

interface Props {
  size?: number;
  variant?: "logo" | "hero";
  title?: string;
}

export function RaccoonMask({ size = 28, variant = "logo", title = "Trash Scan" }: Props) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role="img"
      aria-label={title}
      className={`raccoon raccoon--${variant}`}
    >
      {variant === "hero" && (
        <circle cx="32" cy="35" r="24" className="raccoon-head" />
      )}
      {/* ears */}
      <path
        className="raccoon-ink"
        d="M13 21c-2-9 3-14 9-13 4 1 6 6 5 11-5-2-10-1-14 2Z"
      />
      <path
        className="raccoon-ink"
        d="M51 21c2-9-3-14-9-13-4 1-6 6-5 11 5-2 10-1 14 2Z"
      />
      {/* mask band with eye cut-outs */}
      <path
        className="raccoon-ink"
        fillRule="evenodd"
        clipRule="evenodd"
        d="M7 26c0-8 13-11 25-3 12-8 25-5 25 3 0 11-12 17-19 10-3.5-3.5-8.5-3.5-12 0C19 43 7 37 7 26Zm11 2.5c0-2.6 2.6-4 5-2.7 1.8 1 2.6 3.3 1.8 5.2-.8 1.9-3 2.7-4.8 1.7-1.2-.7-2-2-2-3.4Zm18.4 2.5c-.8-1.9 0-4.2 1.8-5.2 2.4-1.3 5-.1 5 2.7 0 1.4-.8 2.7-2 3.4-1.8 1-4 .2-4.8-1.7Z"
      />
      {/* snout hint */}
      <path
        className="raccoon-ink"
        d="M29 38c1-1.4 5-1.4 6 0 .6 1 0 2.3-1.5 2.8-1.1.3-1.9.3-3 0-1.5-.5-2.1-1.8-1.5-2.8Z"
      />
    </svg>
  );
}
