import { useState } from "react";

interface Props {
  id: string;
  value: string;
  onChange: (v: string) => void;
  minLength?: number;
  required?: boolean;
  placeholder?: string;
  autoComplete?: string;
}

export function PasswordInput({
  id,
  value,
  onChange,
  minLength,
  required,
  placeholder,
  autoComplete = "off",
}: Props) {
  const [show, setShow] = useState(false);
  return (
    <div className="pw-field">
      <input
        id={id}
        type={show ? "text" : "password"}
        value={value}
        minLength={minLength}
        required={required}
        placeholder={placeholder}
        autoComplete={autoComplete}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        type="button"
        className="pw-toggle"
        aria-label={show ? "Hide password" : "Show password"}
        aria-pressed={show}
        title={show ? "Hide password" : "Show password"}
        onClick={() => setShow((s) => !s)}
      >
        {/* raccoon-mask silhouette: hollow eyes when revealed, closed when hidden */}
        <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">
          <path
            fill="currentColor"
            d="M3 11c0-3 5-4.5 9-1.6C16 6.5 21 8 21 11c0 4.2-4.6 6.4-7 3.9-1-1-3-1-4 0C7.6 17.4 3 15.2 3 11Z"
          />
          {show ? (
            <>
              <circle cx="8.7" cy="11.1" r="1.7" fill="var(--charcoal)" />
              <circle cx="15.3" cy="11.1" r="1.7" fill="var(--charcoal)" />
            </>
          ) : (
            <>
              <path d="M7 11.1h3.4" stroke="var(--charcoal)" strokeWidth="1.6" strokeLinecap="round" />
              <path d="M13.6 11.1H17" stroke="var(--charcoal)" strokeWidth="1.6" strokeLinecap="round" />
            </>
          )}
        </svg>
      </button>
    </div>
  );
}
