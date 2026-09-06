// The Trash Scan brand mark: a raccoon head — ears plus the bandit mask with
// true eye cut-outs. Used for the login page and the sidebar brand; the same
// artwork is the favicon (see index.html — keep them in sync).

export function RaccoonMark({ size = 32, tile = false }: { size?: number; tile?: boolean }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Trash Scan"
    >
      {tile && <rect width="64" height="64" rx="13" fill="#171b19" />}
      <path fill="#9db8a6" d="M13 21c-2-9 3-14 9-13 4 1 6 6 5 11-5-2-10-1-14 2Z" />
      <path fill="#9db8a6" d="M51 21c2-9-3-14-9-13-4 1-6 6-5 11 5-2 10-1 14 2Z" />
      <path
        fill="#9db8a6"
        fillRule="evenodd"
        clipRule="evenodd"
        d="M7 27c0-8 13-11 25-3 12-8 25-5 25 3 0 12-13 18-20 11-3-3-7-3-10 0C20 45 7 39 7 27Zm12.5 3a4 4.7 0 1 0 8 0 4 4.7 0 1 0-8 0Zm17 0a4 4.7 0 1 0 8 0 4 4.7 0 1 0-8 0Z"
      />
    </svg>
  );
}
