import { useEffect, useRef, useState } from "react";

export interface Option {
  value: string;
  label: string;
  hint?: string;
}

interface Props {
  label: string;
  options: Option[];
  selected: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  emptyText?: string;
}

export function MultiSelect({
  label,
  options,
  selected,
  onChange,
  placeholder = "Select…",
  emptyText = "Nothing to choose from.",
}: Props) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function toggle(v: string) {
    onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v]);
  }

  const summary =
    selected.length === 0
      ? placeholder
      : selected.length <= 2
        ? options
            .filter((o) => selected.includes(o.value))
            .map((o) => o.label)
            .join(", ")
        : `${selected.length} selected`;

  return (
    <div className="multiselect" ref={ref}>
      <label>{label}</label>
      <button
        type="button"
        className="multiselect__button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span className={selected.length ? "" : "muted"}>{summary}</span>
        <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="multiselect__panel" role="listbox" aria-multiselectable="true">
          {options.length === 0 && <div className="muted multiselect__empty">{emptyText}</div>}
          {options.map((o) => {
            const on = selected.includes(o.value);
            return (
              <button
                key={o.value}
                type="button"
                role="option"
                aria-selected={on}
                className={`multiselect__row ${on ? "on" : ""}`}
                onClick={() => toggle(o.value)}
              >
                <span className="multiselect__check" aria-hidden="true">
                  {on ? "✓" : ""}
                </span>
                <span>
                  {o.label}
                  {o.hint ? <span className="muted"> — {o.hint}</span> : null}
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
