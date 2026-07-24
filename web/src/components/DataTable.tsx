import type { ReactNode } from 'react';
import { clsx } from '../lib/ui';

export interface Column<T> {
  key: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  className?: string;
  width?: string;
}

/**
 * DataTable — a dense, dark, monospace-friendly table for indicator/CVE/scan
 * lists. Rows are optionally clickable (drill-down). Keeps markup minimal so
 * large lists stay responsive.
 */
export function DataTable<T>({
  columns, rows, keyFn, onRowClick, empty,
}: {
  columns: Column<T>[];
  rows: T[];
  keyFn: (row: T) => string;
  onRowClick?: (row: T) => void;
  empty?: ReactNode;
}): JSX.Element {
  if (rows.length === 0 && empty) return <>{empty}</>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-base-600 text-left">
            {columns.map((c) => (
              <th
                key={c.key}
                style={c.width ? { width: c.width } : undefined}
                className="px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-widest text-ink-faint"
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={keyFn(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={clsx(
                'border-b border-base-700/60 transition',
                onRowClick && 'cursor-pointer hover:bg-base-700/40',
              )}
            >
              {columns.map((c) => (
                <td key={c.key} className={clsx('px-3 py-2 align-middle text-ink-dim', c.className)}>
                  {c.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
